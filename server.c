#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <pthread.h>
#include <semaphore.h>
#include <signal.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <arpa/inet.h>
#include <errno.h>
#include <time.h>
#include <sys/stat.h>
#include <ctype.h>
#include <stdarg.h>
#include <openssl/md5.h>

#define PORT 8080
#define MAX_REQUESTS 100
#define THREAD_POOL_SIZE 4
#define BUFFER_SIZE 4096
#define DOCUMENT_ROOT "www"
#define CACHE_SIZE 10
#define LOG_FILE "server_logs.txt"
#define MAX_USERS 10
#define SCHEDULING_FCFS 0
#define SCHEDULING_RR 1

volatile int running = 1;
int current_scheduling_algorithm = SCHEDULING_FCFS; // Default scheduling

typedef struct
{
    char username[32];
    char password_hash[64]; // Simple hash storage
} user_auth_t;

// User authentication database
user_auth_t users[MAX_USERS] = {
    {"admin", "5f4dcc3b5aa765d61d8327deb882cf99"}, // Password: password
    {"user", "ee11cbb19052e40b07aac0ca060c23ee"}   // Password: user
};
int user_count = 2;

// ========== CACHE SYSTEM ==========
typedef struct
{
    char path[256];
    char content[BUFFER_SIZE * 2];
    int content_length;
    time_t timestamp;
    int hits;
} cache_entry_t;

typedef struct
{
    cache_entry_t entries[CACHE_SIZE];
    int count;
    pthread_mutex_t mutex;
} cache_t;

cache_t cache = {
    .count = 0,
    .mutex = PTHREAD_MUTEX_INITIALIZER};

// ========== SHARED MEMORY STATS ==========
typedef struct
{
    pthread_mutex_t stats_mutex;
    int total_requests;
    int active_connections;
    int cache_hits;
    int cache_misses;
} server_stats_t;

server_stats_t *shared_stats;

// ========== LOGGING SYSTEM ==========
pthread_mutex_t log_mutex = PTHREAD_MUTEX_INITIALIZER;

void log_message(const char *format, ...)
{
    pthread_mutex_lock(&log_mutex);

    FILE *log_file = fopen(LOG_FILE, "a");
    if (log_file)
    {
        time_t now = time(NULL);
        char time_str[64];
        strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", localtime(&now));

        fprintf(log_file, "[%s] ", time_str);

        va_list args;
        va_start(args, format);
        vfprintf(log_file, format, args);
        va_end(args);

        fprintf(log_file, "\n");
        fclose(log_file);
    }

    pthread_mutex_unlock(&log_mutex);
}

// ========== READER-WRITER PROBLEM ==========
typedef struct
{
    pthread_mutex_t mutex;
    pthread_cond_t read, write;
    int readers;
    int writers;
    int waiting_writers;
} rw_lock_t;

rw_lock_t rw_lock = {
    .mutex = PTHREAD_MUTEX_INITIALIZER,
    .read = PTHREAD_COND_INITIALIZER,
    .write = PTHREAD_COND_INITIALIZER,
    .readers = 0,
    .writers = 0,
    .waiting_writers = 0};

void reader_lock()
{
    pthread_mutex_lock(&rw_lock.mutex);

    while (rw_lock.writers > 0 || rw_lock.waiting_writers > 0)
        pthread_cond_wait(&rw_lock.read, &rw_lock.mutex);

    rw_lock.readers++;
    pthread_mutex_unlock(&rw_lock.mutex);
}

void reader_unlock()
{
    pthread_mutex_lock(&rw_lock.mutex);
    rw_lock.readers--;

    if (rw_lock.readers == 0)
        pthread_cond_signal(&rw_lock.write);

    pthread_mutex_unlock(&rw_lock.mutex);
}

void writer_lock()
{
    pthread_mutex_lock(&rw_lock.mutex);

    rw_lock.waiting_writers++;
    while (rw_lock.writers > 0 || rw_lock.readers > 0)
        pthread_cond_wait(&rw_lock.write, &rw_lock.mutex);

    rw_lock.waiting_writers--;
    rw_lock.writers++;
    pthread_mutex_unlock(&rw_lock.mutex);
}

void writer_unlock()
{
    pthread_mutex_lock(&rw_lock.mutex);
    rw_lock.writers--;

    if (rw_lock.waiting_writers > 0)
        pthread_cond_signal(&rw_lock.write);
    else
        pthread_cond_broadcast(&rw_lock.read);

    pthread_mutex_unlock(&rw_lock.mutex);
}

// ========== PRODUCER-CONSUMER QUEUE ==========
typedef struct
{
    int client_socket;
    char path[256];
    char method[16];
    char query[256];
    time_t arrival_time;
    int priority; // For scheduling
} request_t;

typedef struct
{
    request_t requests[MAX_REQUESTS];
    int front, rear, count;
    pthread_mutex_t mutex;
    pthread_cond_t not_empty;
    pthread_cond_t not_full;
} request_queue_t;

request_queue_t request_queue = {
    .front = 0,
    .rear = 0,
    .count = 0,
    .mutex = PTHREAD_MUTEX_INITIALIZER,
    .not_empty = PTHREAD_COND_INITIALIZER,
    .not_full = PTHREAD_COND_INITIALIZER};

void md5_hash(const char *input, char *output)
{
    unsigned char digest[16];
    MD5((unsigned char *)input, strlen(input), digest);

    for (int i = 0; i < 16; i++)
    {
        sprintf(&output[i * 2], "%02x", digest[i]);
    }
    output[32] = '\0';
}
void base64_decode(const char *input, char *output)
{
    static const char table[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    int input_length = strlen(input);
    int i, j;
    char *p = output;

    for (i = 0; i < input_length; i += 4)
    {
        int n = 0;
        int valid_chars = 0;

        for (j = 0; j < 4 && i + j < input_length; j++)
        {
            char c = input[i + j];
            if (c == '=')
                break;

            const char *pos = strchr(table, c);
            if (pos)
            {
                n = n << 6 | (pos - table);
                valid_chars++;
            }
        }

        if (valid_chars >= 2)
            *p++ = (n >> 16) & 0xFF;
        if (valid_chars >= 3)
            *p++ = (n >> 8) & 0xFF;
        if (valid_chars >= 4)
            *p++ = n & 0xFF;
    }

    *p = '\0';
}

int authenticate_user(const char *auth_header)
{
    log_message("Auth header: %s", auth_header ? auth_header : "NULL");

    if (!auth_header || strncmp(auth_header, "Basic ", 6) != 0)
    {
        log_message("Authentication failed: Invalid header format");
        return 0;
    }

    // Skip "Basic " prefix
    const char *encoded = auth_header + 6;

    // Decode Base64
    char decoded[128] = {0}; // Initialize to zeros
    base64_decode(encoded, decoded);

    // Find the colon separating username and password
    char *colon = strchr(decoded, ':');
    if (!colon)
    {
        log_message("Authentication failed: No colon in decoded credentials");
        return 0;
    }

    // Split username and password
    *colon = '\0';
    char *username = decoded;
    char *password = colon + 1;

    if (!username || strlen(username) == 0 || !password || strlen(password) == 0)
    {
        log_message("Authentication failed: Empty username or password");
        return 0;
    }

    log_message("Attempting authentication for user: %s", username);

    char hashed_pwd[64];
    md5_hash(password, hashed_pwd);

    for (int i = 0; i < user_count; i++)
    {
        if (strcmp(username, users[i].username) == 0 &&
            strcmp(hashed_pwd, users[i].password_hash) == 0)
        {
            log_message("Authentication successful for user: %s", username);
            return 1;
        }
    }

    log_message("Authentication failed: Invalid credentials for user: %s", username);
    return 0;
}

// ========== CACHE FUNCTIONS ==========
int check_cache(const char *path, char *content, int *content_length)
{
    pthread_mutex_lock(&cache.mutex);

    for (int i = 0; i < cache.count; i++)
    {
        if (strcmp(path, cache.entries[i].path) == 0)
        {
            cache.entries[i].hits++;
            *content_length = cache.entries[i].content_length;
            memcpy(content, cache.entries[i].content, cache.entries[i].content_length);

            pthread_mutex_lock(&shared_stats->stats_mutex);
            shared_stats->cache_hits++;
            pthread_mutex_unlock(&shared_stats->stats_mutex);

            pthread_mutex_unlock(&cache.mutex);
            return 1;
        }
    }

    pthread_mutex_lock(&shared_stats->stats_mutex);
    shared_stats->cache_misses++;
    pthread_mutex_unlock(&shared_stats->stats_mutex);

    pthread_mutex_unlock(&cache.mutex);
    return 0;
}

void add_to_cache(const char *path, const char *content, int content_length)
{
    if (content_length > BUFFER_SIZE * 2 || strlen(path) > 255)
    {
        return; // Too large for cache
    }

    pthread_mutex_lock(&cache.mutex);

    // Check if already in cache
    for (int i = 0; i < cache.count; i++)
    {
        if (strcmp(path, cache.entries[i].path) == 0)
        {
            // Update existing entry
            memcpy(cache.entries[i].content, content, content_length);
            cache.entries[i].content_length = content_length;
            cache.entries[i].timestamp = time(NULL);

            pthread_mutex_unlock(&cache.mutex);
            return;
        }
    }

    // Add new entry (replace least used if cache is full)
    if (cache.count < CACHE_SIZE)
    {
        strcpy(cache.entries[cache.count].path, path);
        memcpy(cache.entries[cache.count].content, content, content_length);
        cache.entries[cache.count].content_length = content_length;
        cache.entries[cache.count].timestamp = time(NULL);
        cache.entries[cache.count].hits = 1;
        cache.count++;
    }
    else
    {
        // Find entry with least hits
        int min_hits = cache.entries[0].hits;
        int min_idx = 0;

        for (int i = 1; i < CACHE_SIZE; i++)
        {
            if (cache.entries[i].hits < min_hits)
            {
                min_hits = cache.entries[i].hits;
                min_idx = i;
            }
        }

        // Replace it
        strcpy(cache.entries[min_idx].path, path);
        memcpy(cache.entries[min_idx].content, content, content_length);
        cache.entries[min_idx].content_length = content_length;
        cache.entries[min_idx].timestamp = time(NULL);
        cache.entries[min_idx].hits = 1;
    }

    pthread_mutex_unlock(&cache.mutex);
}

// ========== CGI REQUEST HANDLER ==========
int is_cgi_request(const char *path)
{
    return (strstr(path, ".cgi") != NULL || strstr(path, "/cgi-bin/") != NULL);
}

void handle_cgi_request(int client_socket, const char *path, const char *query_string, const char *method)
{
    int cgi_output[2], cgi_input[2];
    if (pipe(cgi_output) < 0 || pipe(cgi_input) < 0)
    {
        send(client_socket, "HTTP/1.1 500 Internal Server Error\r\n\r\n", 38, 0);
        log_message("CGI error: Failed to create pipes for %s", path);
        return;
    }

    pid_t pid = fork();
    if (pid < 0)
    {
        close(cgi_output[0]);
        close(cgi_output[1]);
        close(cgi_input[0]);
        close(cgi_input[1]);
        send(client_socket, "HTTP/1.1 500 Internal Server Error\r\n\r\n", 38, 0);
        log_message("CGI error: Failed to fork for %s", path);
        return;
    }

    if (pid == 0)
    {
        dup2(cgi_input[0], STDIN_FILENO);
        dup2(cgi_output[1], STDOUT_FILENO);
        close(cgi_output[0]);
        close(cgi_input[1]);

        setenv("QUERY_STRING", query_string ? query_string : "", 1);
        setenv("REQUEST_METHOD", method, 1);
        setenv("CONTENT_LENGTH", "0", 1);
        setenv("SCRIPT_NAME", path, 1);

        execl(path, path, NULL);
        log_message("CGI error: Failed to execute %s", path);
        exit(1);
    }
    else
    {
        close(cgi_output[1]);
        close(cgi_input[0]);

        if (query_string && strchr(query_string, '='))
        {
            write(cgi_input[1], query_string, strlen(query_string));
        }
        close(cgi_input[1]);

        send(client_socket, "HTTP/1.1 200 OK\r\n", 17, 0);

        char buffer[BUFFER_SIZE];
        ssize_t bytes_read;
        while ((bytes_read = read(cgi_output[0], buffer, BUFFER_SIZE)) > 0)
        {
            send(client_socket, buffer, bytes_read, 0);
        }

        close(cgi_output[0]);
        waitpid(pid, NULL, 0);
        log_message("CGI request processed: %s", path);
    }
}

// ========== STATIC FILE HANDLER ==========
const char *get_content_type(const char *path)
{
    const char *ext = strrchr(path, '.');
    if (!ext)
        return "text/plain";

    if (strcmp(ext, ".html") == 0 || strcmp(ext, ".htm") == 0)
        return "text/html";
    if (strcmp(ext, ".css") == 0)
        return "text/css";
    if (strcmp(ext, ".js") == 0)
        return "application/javascript";
    if (strcmp(ext, ".jpg") == 0 || strcmp(ext, ".jpeg") == 0)
        return "image/jpeg";
    if (strcmp(ext, ".png") == 0)
        return "image/png";
    if (strcmp(ext, ".gif") == 0)
        return "image/gif";
    if (strcmp(ext, ".txt") == 0)
        return "text/plain";

    return "application/octet-stream";
}

void send_404(int sock)
{
    FILE *fp = fopen("www/404.html", "r");
    char buffer[BUFFER_SIZE];
    if (!fp)
    {
        snprintf(buffer, sizeof(buffer), "HTTP/1.1 404 Not Found\r\n\r\n404 Not Found");
        send(sock, buffer, strlen(buffer), 0);
        log_message("404 Not Found: Custom 404 page not available");
        return;
    }

    send(sock, "HTTP/1.1 404 Not Found\r\nContent-Type: text/html\r\n\r\n", 53, 0);

    while (fgets(buffer, BUFFER_SIZE, fp))
        send(sock, buffer, strlen(buffer), 0);

    fclose(fp);
    log_message("404 Not Found: Sent custom 404 page");
}

void send_401(int sock)
{
    char buffer[BUFFER_SIZE];
    snprintf(buffer, sizeof(buffer),
             "HTTP/1.1 401 Unauthorized\r\n"
             "WWW-Authenticate: Basic realm=\"Web Server\"\r\n"
             "Content-Type: text/html\r\n"
             "\r\n"
             "<html><head><title>401 Unauthorized</title></head>"
             "<body><h1>401 Unauthorized</h1>"
             "<p>Authentication is required to access this resource.</p>"
             "</body></html>");

    send(sock, buffer, strlen(buffer), 0);
    log_message("401 Unauthorized: Authentication required");
}

void handle_static_file(int client_socket, const char *path, int requires_auth, const char *auth_header)
{
    if (requires_auth && !authenticate_user(auth_header))
    {
        send_401(client_socket);
        return;
    }

    // Check if the file is in cache
    char content[BUFFER_SIZE * 2];
    int content_length;

    if (check_cache(path, content, &content_length))
    {
        // Found in cache
        const char *content_type = get_content_type(path);
        char header[512];
        snprintf(header, sizeof(header),
                 "HTTP/1.1 200 OK\r\n"
                 "Content-Type: %s\r\n"
                 "Content-Length: %d\r\n"
                 "X-Cache: HIT\r\n"
                 "\r\n",
                 content_type, content_length);

        send(client_socket, header, strlen(header), 0);
        send(client_socket, content, content_length, 0);

        log_message("Served from cache: %s", path);
        return;
    }

    // Not in cache, read from disk
    FILE *fp = fopen(path, "rb");
    if (!fp)
    {
        send_404(client_socket);
        return;
    }

    // Get file size for Content-Length header
    fseek(fp, 0, SEEK_END);
    long file_size = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    const char *content_type = get_content_type(path);
    char header[512];
    snprintf(header, sizeof(header),
             "HTTP/1.1 200 OK\r\n"
             "Content-Type: %s\r\n"
             "Content-Length: %ld\r\n"
             "X-Cache: MISS\r\n"
             "\r\n",
             content_type, file_size);

    send(client_socket, header, strlen(header), 0);

    // Use writer lock for reading file (ensures exclusive access during cache update)
    writer_lock();

    // Read and send file content
    char buffer[BUFFER_SIZE];
    size_t bytes_read;
    long total_read = 0;

    // Only cache text-based files
    int cacheable = (strstr(content_type, "text/") == content_type ||
                     strstr(content_type, "application/javascript") == content_type);

    if (cacheable && file_size < BUFFER_SIZE * 2)
    {
        char *cache_buffer = malloc(file_size);
        if (cache_buffer)
        {
            long cache_pos = 0;

            while ((bytes_read = fread(buffer, 1, sizeof(buffer), fp)) > 0)
            {
                send(client_socket, buffer, bytes_read, 0);

                if (cache_pos + bytes_read <= file_size)
                {
                    memcpy(cache_buffer + cache_pos, buffer, bytes_read);
                    cache_pos += bytes_read;
                }

                total_read += bytes_read;
            }

            if (total_read == file_size)
            {
                add_to_cache(path, cache_buffer, file_size);
            }

            free(cache_buffer);
        }
    }
    else
    {
        while ((bytes_read = fread(buffer, 1, sizeof(buffer), fp)) > 0)
        {
            send(client_socket, buffer, bytes_read, 0);
        }
    }

    fclose(fp);
    writer_unlock();

    log_message("Served file: %s (%ld bytes)", path, file_size);
}

// ========== HTTP REQUEST PARSER ==========
void parse_http_request(const char *request, char *method, char *path, char *query, char *auth_header)
{
    method[0] = path[0] = query[0] = '\0';
    if (auth_header != NULL)
    {
        auth_header[0] = '\0';
    }

    // Get method and path
    sscanf(request, "%15s %255s", method, path);

    // Extract query string
    char *q = strchr(path, '?');
    if (q)
    {
        *q = '\0';
        strncpy(query, q + 1, 255);
        query[255] = '\0';
    }

    // Extract Authorization header
    if (auth_header != NULL)
    {
        const char *auth = strstr(request, "Authorization: ");
        if (auth)
        {
            auth += 15; // Skip "Authorization: "
            const char *auth_end = strstr(auth, "\r\n");
            if (auth_end)
            {
                int auth_len = auth_end - auth;
                if (auth_len < 255)
                {
                    strncpy(auth_header, auth, auth_len);
                    auth_header[auth_len] = '\0';
                }
            }
        }
    }
}
void handle_http_request(int client_socket)
{
    char buffer[BUFFER_SIZE];
    memset(buffer, 0, sizeof(buffer));
    int bytes_received = recv(client_socket, buffer, sizeof(buffer) - 1, 0);

    if (bytes_received <= 0)
    {
        log_message("Empty request received");
        return;
    }

    // Parse request
    char method[16], path[256], query[256] = "", auth_header[256] = ""; // Ensure auth_header is always initialized
    parse_http_request(buffer, method, path, query, auth_header);

    // Update statistics
    pthread_mutex_lock(&shared_stats->stats_mutex);
    shared_stats->total_requests++;
    shared_stats->active_connections++;
    pthread_mutex_unlock(&shared_stats->stats_mutex);

    // Log request
    log_message("Request: %s %s?%s", method, path, query);

    // Handle special paths
    if (strcmp(path, "/stats") == 0)
    {
        // Use reader lock for accessing stats
        reader_lock();

        char stats_buffer[BUFFER_SIZE];
        snprintf(stats_buffer, sizeof(stats_buffer),
                 "HTTP/1.1 200 OK\r\n"
                 "Content-Type: text/html\r\n"
                 "\r\n"
                 "<html><head><title>Server Statistics</title></head>"
                 "<body><h1>Server Statistics</h1>"
                 "<p>Total Requests: %d</p>"
                 "<p>Active Connections: %d</p>"
                 "<p>Cache Hits: %d</p>"
                 "<p>Cache Misses: %d</p>"
                 "</body></html>",
                 shared_stats->total_requests,
                 shared_stats->active_connections,
                 shared_stats->cache_hits,
                 shared_stats->cache_misses);

        send(client_socket, stats_buffer, strlen(stats_buffer), 0);
        reader_unlock();

        log_message("Served statistics page");
    }
    else
    {
        char full_path[512];
        snprintf(full_path, sizeof(full_path), "%s%s",
                 DOCUMENT_ROOT,
                 strcmp(path, "/") == 0 ? "/index.html" : path);

        if (is_cgi_request(full_path))
        {
            handle_cgi_request(client_socket, full_path, query, method);
        }
        else
        {
            // Check if path requires authentication (secure area)
            int requires_auth = (strstr(path, "/secure/") != NULL);
            handle_static_file(client_socket, full_path, requires_auth, auth_header);
        }
    }

    pthread_mutex_lock(&shared_stats->stats_mutex);
    shared_stats->active_connections--;
    pthread_mutex_unlock(&shared_stats->stats_mutex);
}

// ========== SCHEDULING ALGORITHMS ==========
request_t get_next_request()
{
    request_t request;
    pthread_mutex_lock(&request_queue.mutex);

    while (request_queue.count == 0 && running)
        pthread_cond_wait(&request_queue.not_empty, &request_queue.mutex);

    if (!running)
    {
        request.client_socket = -1;
        pthread_mutex_unlock(&request_queue.mutex);
        return request;
    }

    if (current_scheduling_algorithm == SCHEDULING_FCFS)
    {
        // First-Come First-Served (simple queue)
        request = request_queue.requests[request_queue.front];
        request_queue.front = (request_queue.front + 1) % MAX_REQUESTS;
    }
    else
    {
        // Round Robin with priority
        int selected_index = request_queue.front;
        time_t current_time = time(NULL);

        // Try to find request with highest priority or oldest waiting time
        for (int i = 0; i < request_queue.count; i++)
        {
            int idx = (request_queue.front + i) % MAX_REQUESTS;
            if (request_queue.requests[idx].priority > request_queue.requests[selected_index].priority ||
                (request_queue.requests[idx].priority == request_queue.requests[selected_index].priority &&
                 request_queue.requests[idx].arrival_time < request_queue.requests[selected_index].arrival_time))
            {
                selected_index = idx;
            }
        }

        // Get the selected request
        request = request_queue.requests[selected_index];

        // Reorganize queue (remove the selected item)
        for (int i = 0; i < request_queue.count - 1; i++)
        {
            int curr = (selected_index + i) % MAX_REQUESTS;
            int next = (selected_index + i + 1) % MAX_REQUESTS;
            request_queue.requests[curr] = request_queue.requests[next];
        }
    }

    request_queue.count--;
    pthread_cond_signal(&request_queue.not_full);
    pthread_mutex_unlock(&request_queue.mutex);

    log_message("Scheduled request %s %s", request.method, request.path);
    return request;
}

// ========== THREAD POOL ==========
void *worker_thread(void *arg)
{
    while (running)
    {
        request_t request = get_next_request();

        if (request.client_socket < 0)
            break;

        handle_http_request(request.client_socket);
        close(request.client_socket);
    }
    return NULL;
}

void enqueue_request(int client_socket, const char *method, const char *path, const char *query)
{
    pthread_mutex_lock(&request_queue.mutex);
    while (request_queue.count == MAX_REQUESTS && running)
        pthread_cond_wait(&request_queue.not_full, &request_queue.mutex);

    if (!running)
    {
        pthread_mutex_unlock(&request_queue.mutex);
        return;
    }

    // Create a new request
    request_t *req = &request_queue.requests[request_queue.rear];
    req->client_socket = client_socket;
    strncpy(req->method, method, sizeof(req->method) - 1);
    strncpy(req->path, path, sizeof(req->path) - 1);
    strncpy(req->query, query, sizeof(req->query) - 1);
    req->arrival_time = time(NULL);

    // Set priority (can be based on path, client IP, etc.)
    if (strstr(path, "/secure/") != NULL)
    {
        req->priority = 2; // Higher priority for secure content
    }
    else if (strstr(path, "/cgi-bin/") != NULL)
    {
        req->priority = 1; // Medium priority for dynamic content
    }
    else
    {
        req->priority = 0; // Normal priority for static content
    }

    request_queue.rear = (request_queue.rear + 1) % MAX_REQUESTS;
    request_queue.count++;

    pthread_cond_signal(&request_queue.not_empty);
    pthread_mutex_unlock(&request_queue.mutex);

    log_message("Enqueued request %s %s", method, path);
}

void init_thread_pool()
{
    pthread_t *workers = malloc(THREAD_POOL_SIZE * sizeof(pthread_t));
    if (!workers)
    {
        perror("Failed to allocate memory for thread pool");
        exit(1);
    }

    for (int i = 0; i < THREAD_POOL_SIZE; i++)
    {
        if (pthread_create(&workers[i], NULL, worker_thread, NULL) != 0)
        {
            perror("Failed to create worker thread");
            exit(1);
        }
    }

    log_message("Thread pool initialized with %d threads", THREAD_POOL_SIZE);
}

// ========== DEADLOCK DETECTION ==========
typedef struct
{
    int thread_id;
    int resource_held;
    int resource_waiting;
    int status; // 0=idle, 1=running, 2=blocked
} thread_status_t;

thread_status_t thread_statuses[THREAD_POOL_SIZE];

void init_deadlock_detection()
{
    for (int i = 0; i < THREAD_POOL_SIZE; i++)
    {
        thread_statuses[i].thread_id = i;
        thread_statuses[i].resource_held = -1;
        thread_statuses[i].resource_waiting = -1;
        thread_statuses[i].status = 0;
    }
}
// Continuing from the check_deadlock function
int check_deadlock()
{
    // Simple cycle detection in resource allocation graph
    for (int i = 0; i < THREAD_POOL_SIZE; i++)
    {
        if (thread_statuses[i].status == 2)
        { // If blocked
            int current = i;
            int visited[THREAD_POOL_SIZE] = {0};

            while (1)
            {
                visited[current] = 1;
                int waiting_for = thread_statuses[current].resource_waiting;

                if (waiting_for == -1)
                {
                    break; // Not waiting for any resource
                }

                // Find thread holding this resource
                int holder = -1;
                for (int j = 0; j < THREAD_POOL_SIZE; j++)
                {
                    if (thread_statuses[j].resource_held == waiting_for)
                    {
                        holder = j;
                        break;
                    }
                }

                if (holder == -1)
                {
                    break; // Resource not held by any thread
                }

                if (visited[holder])
                {
                    return 1; // Cycle detected - deadlock found
                }

                current = holder;
            }
        }
    }

    return 0; // No deadlock detected
}

void deadlock_detection_thread()
{
    while (running)
    {
        sleep(5);

        if (check_deadlock())
        {
            log_message("DEADLOCK DETECTED: Attempting recovery");

            // Simple recovery: reset blocked threads with lowest priority
            for (int i = 0; i < THREAD_POOL_SIZE; i++)
            {
                if (thread_statuses[i].status == 2)
                { // If blocked
                    thread_statuses[i].status = 1;
                    thread_statuses[i].resource_waiting = -1;
                    log_message("Reset thread %d to resolve deadlock", i);
                    break;
                }
            }
        }
    }
}

// ========== LOAD BALANCER ==========
typedef struct
{
    int servers[2]; // Array of server file descriptors
    int server_count;
    int current_server;
    pthread_mutex_t mutex;
} load_balancer_t;

load_balancer_t load_balancer = {
    .server_count = 0,
    .current_server = 0,
    .mutex = PTHREAD_MUTEX_INITIALIZER};

void add_server_to_load_balancer(int server_socket)
{
    pthread_mutex_lock(&load_balancer.mutex);

    if (load_balancer.server_count < 2)
    {
        load_balancer.servers[load_balancer.server_count++] = server_socket;
        log_message("Added server #%d to load balancer", load_balancer.server_count);
    }
    else
    {
        log_message("Maximum number of servers already reached in load balancer");
    }

    pthread_mutex_unlock(&load_balancer.mutex);
}

int get_next_server()
{
    pthread_mutex_lock(&load_balancer.mutex);

    if (load_balancer.server_count == 0)
    {
        pthread_mutex_unlock(&load_balancer.mutex);
        return -1;
    }

    // Round robin selection
    int server = load_balancer.servers[load_balancer.current_server];
    load_balancer.current_server = (load_balancer.current_server + 1) % load_balancer.server_count;

    pthread_mutex_unlock(&load_balancer.mutex);
    return server;
}

// ========== VIRTUAL MEMORY PAGING SIMULATION ==========
#define PAGE_SIZE 4096
#define PAGE_TABLE_SIZE 1024

typedef struct
{
    int valid;
    void *frame_ptr;
    int dirty;
    time_t last_access;
} page_t;

typedef struct
{
    page_t pages[PAGE_TABLE_SIZE];
    int page_count;
    pthread_mutex_t mutex;
} page_table_t;

page_table_t page_table = {
    .page_count = 0,
    .mutex = PTHREAD_MUTEX_INITIALIZER};

void *allocate_page()
{
    pthread_mutex_lock(&page_table.mutex);

    void *page = NULL;
    if (page_table.page_count < PAGE_TABLE_SIZE)
    {
        // Allocate a new page
        page = mmap(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

        if (page != MAP_FAILED)
        {
            page_table.pages[page_table.page_count].valid = 1;
            page_table.pages[page_table.page_count].frame_ptr = page;
            page_table.pages[page_table.page_count].dirty = 0;
            page_table.pages[page_table.page_count].last_access = time(NULL);
            page_table.page_count++;

            log_message("Allocated page #%d at %p", page_table.page_count - 1, page);
        }
        else
        {
            log_message("Failed to allocate page: %s", strerror(errno));
        }
    }
    else
    {
        // Page replacement using LRU
        int oldest_idx = 0;
        time_t oldest_time = page_table.pages[0].last_access;

        for (int i = 1; i < page_table.page_count; i++)
        {
            if (page_table.pages[i].last_access < oldest_time)
            {
                oldest_time = page_table.pages[i].last_access;
                oldest_idx = i;
            }
        }

        page = page_table.pages[oldest_idx].frame_ptr;

        // If dirty, need to "write back" (simulate)
        if (page_table.pages[oldest_idx].dirty)
        {
            log_message("Writing back dirty page #%d before reuse", oldest_idx);
            // Simulate write back by clearing the page
            memset(page, 0, PAGE_SIZE);
        }

        page_table.pages[oldest_idx].dirty = 0;
        page_table.pages[oldest_idx].last_access = time(NULL);

        log_message("Reused page #%d at %p", oldest_idx, page);
    }

    pthread_mutex_unlock(&page_table.mutex);
    return page;
}

void *page_access(int page_idx)
{
    if (page_idx < 0 || page_idx >= page_table.page_count)
    {
        log_message("Invalid page access: %d", page_idx);
        return NULL;
    }

    pthread_mutex_lock(&page_table.mutex);

    // Page fault simulation
    if (!page_table.pages[page_idx].valid)
    {
        log_message("Page fault on access to page #%d", page_idx);

        // Allocate new frame for the page
        void *frame = mmap(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

        if (frame != MAP_FAILED)
        {
            page_table.pages[page_idx].frame_ptr = frame;
            page_table.pages[page_idx].valid = 1;
        }
        else
        {
            log_message("Failed to handle page fault: %s", strerror(errno));
            pthread_mutex_unlock(&page_table.mutex);
            return NULL;
        }
    }

    // Update access time
    page_table.pages[page_idx].last_access = time(NULL);
    void *ptr = page_table.pages[page_idx].frame_ptr;

    pthread_mutex_unlock(&page_table.mutex);
    return ptr;
}

void mark_page_dirty(int page_idx)
{
    if (page_idx >= 0 && page_idx < page_table.page_count)
    {
        pthread_mutex_lock(&page_table.mutex);
        page_table.pages[page_idx].dirty = 1;
        pthread_mutex_unlock(&page_table.mutex);

        log_message("Marked page #%d as dirty", page_idx);
    }
}

// ========== SIGNAL HANDLERS ==========
void handle_signal(int sig)
{
    if (sig == SIGINT || sig == SIGTERM)
    {
        log_message("Received signal %d. Shutting down...", sig);
        running = 0;

        // Wake up all threads waiting on condition variables
        pthread_cond_broadcast(&request_queue.not_empty);
        pthread_cond_broadcast(&request_queue.not_full);
    }
}

// ========== MAIN SERVER FUNCTION ==========
int start_server(int port)
{
    int server_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (server_socket < 0)
    {
        perror("Failed to create socket");
        return -1;
    }

    // Set socket options to reuse address
    int opt = 1;
    if (setsockopt(server_socket, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)))
    {
        perror("Failed to set socket options");
        close(server_socket);
        return -1;
    }

    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(port);

    if (bind(server_socket, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0)
    {
        perror("Failed to bind to port");
        close(server_socket);
        return -1;
    }

    if (listen(server_socket, SOMAXCONN) < 0)
    {
        perror("Failed to listen on socket");
        close(server_socket);
        return -1;
    }

    log_message("Server started on port %d", port);
    return server_socket;
}

// Thread to periodically clean stale cache entries
void *cache_cleaner_thread(void *arg)
{
    while (running)
    {
        sleep(120); // Run every 2 minutes

        pthread_mutex_lock(&cache.mutex);
        time_t now = time(NULL);

        for (int i = 0; i < cache.count; i++)
        {
            // If cache entry is older than 30 minutes and has low hits
            if (now - cache.entries[i].timestamp > 1800 && cache.entries[i].hits < 5)
            {
                // Remove by shifting remaining entries
                for (int j = i; j < cache.count - 1; j++)
                {
                    cache.entries[j] = cache.entries[j + 1];
                }
                cache.count--;
                i--; // Adjust index for the next iteration

                log_message("Removed stale cache entry");
            }
        }

        pthread_mutex_unlock(&cache.mutex);
    }

    return NULL;
}

// ========== MAIN FUNCTION ==========
int main(int argc, char *argv[])
{
    int port = PORT;

    // Parse command line arguments
    for (int i = 1; i < argc; i++)
    {
        if (strcmp(argv[i], "-p") == 0 && i + 1 < argc)
        {
            port = atoi(argv[i + 1]);
            i++;
        }
        else if (strcmp(argv[i], "-s") == 0 && i + 1 < argc)
        {
            if (strcmp(argv[i + 1], "fcfs") == 0)
            {
                current_scheduling_algorithm = SCHEDULING_FCFS;
            }
            else if (strcmp(argv[i + 1], "rr") == 0)
            {
                current_scheduling_algorithm = SCHEDULING_RR;
            }
            i++;
        }
    }

    // Set up signal handlers
    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);

    // Initialize server statistics in shared memory
    shared_stats = mmap(NULL, sizeof(server_stats_t),
                        PROT_READ | PROT_WRITE,
                        MAP_SHARED | MAP_ANONYMOUS, -1, 0);

    if (shared_stats == MAP_FAILED)
    {
        perror("Failed to allocate shared memory for statistics");
        return 1;
    }

    shared_stats->total_requests = 0;
    shared_stats->active_connections = 0;
    shared_stats->cache_hits = 0;
    shared_stats->cache_misses = 0;
    pthread_mutex_init(&shared_stats->stats_mutex, NULL);

    // Create directories if they don't exist
    mkdir(DOCUMENT_ROOT, 0755);
    mkdir("www/secure", 0755);
    mkdir("www/cgi-bin", 0755);

    // Initialize thread pool and other subsystems
    init_thread_pool();
    init_deadlock_detection();

    // Create cache cleaner thread
    pthread_t cache_cleaner;
    pthread_create(&cache_cleaner, NULL, cache_cleaner_thread, NULL);

    // Start main server socket
    int server_socket = start_server(port);
    if (server_socket < 0)
    {
        return 1;
    }

    log_message("Server initialized with %s scheduling",
                current_scheduling_algorithm == SCHEDULING_FCFS ? "FCFS" : "Round Robin");

    // Main accept loop
    struct sockaddr_in client_addr;
    socklen_t client_len = sizeof(client_addr);
    int client_socket;

    while (running)
    {
        client_socket = accept(server_socket, (struct sockaddr *)&client_addr, &client_len);

        if (client_socket < 0)
        {
            if (errno == EINTR && !running)
            {
                break; // Server is shutting down
            }

            perror("Error accepting connection");
            continue;
        }

        // Receive request header to determine method and path
        char buffer[BUFFER_SIZE] = {0};
        recv(client_socket, buffer, sizeof(buffer) - 1, MSG_PEEK);

        char method[16], path[256], query[256];
        parse_http_request(buffer, method, path, query, NULL);

        log_message("Connection from %s:%d - %s %s",
                    inet_ntoa(client_addr.sin_addr),
                    ntohs(client_addr.sin_port),
                    method, path);

        // Enqueue the request for processing by thread pool
        enqueue_request(client_socket, method, path, query);
    }

    // Clean up resources
    close(server_socket);

    // Wait for all threads to finish
    running = 0;
    pthread_cond_broadcast(&request_queue.not_empty);
    pthread_cond_broadcast(&request_queue.not_full);

    // Wait for cache cleaner to finish
    pthread_join(cache_cleaner, NULL);

    // Clean up shared memory
    munmap(shared_stats, sizeof(server_stats_t));

    log_message("Server shutdown complete");
    return 0;
}