/*
====================================================================
        AI-POWERED EXE DEOBFUSCATION / STATIC ANALYSIS
                         C + Gemini API
====================================================================

FLOW:

        sample.exe
            |
            | raw bytes
            v
     Gemini Files API
            |
            v
        file URI
            |
            v
     Gemini 3.7 Flash
            |
            v
   AI static analysis
            |
            +---- Obfuscation
            +---- Deobfuscation / pseudocode
            +---- Behavior
            +---- Suspicious indicators
            +---- Risk score
            |
            v
     gemini_result.json

IMPORTANT:
    - The EXE is NEVER executed.
    - This is static analysis.
    - AI cannot always recover original source code.
    - Do not treat AI output as proof of malware.
====================================================================
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <curl/curl.h>

/*
    _strnicmp is MSVC/Windows-only. On POSIX systems
    (Linux, macOS) the equivalent is strncasecmp.
    This macro makes the code portable to both.
*/
#ifndef _WIN32
    #define _strnicmp strncasecmp
#endif

/*
    Current stable model.

    You can change this later to another currently available
    Gemini model if your API account supports it.
*/
#define GEMINI_MODEL "gemini-3.7-flash"

#define FILE_UPLOAD_ENDPOINT \
    "https://generativelanguage.googleapis.com/upload/v1beta/files"

#define GENERATE_ENDPOINT \
    "https://generativelanguage.googleapis.com/v1beta/models/" \
    GEMINI_MODEL ":generateContent"

/*
    Gemini's context window is measured in TOKENS, not bytes.
    Raw binary data tokenizes far less efficiently than text
    (roughly 1 token per few bytes, sometimes worse), so a
    multi-MB EXE can blow past the 1,048,576 token limit even
    though the file itself seems small enough.

    To stay safely under that limit we only upload the first
    MAX_UPLOAD_BYTES of the file by default (this generally
    covers headers, early sections, and the entry point, which
    is where most static-analysis signal lives). Override with
    a third CLI argument, e.g.:

        analyzer sample.exe 800000

    NOTE: this is a stopgap. The more correct long-term fix is
    to stop sending raw bytes at all and instead extract PE
    headers/sections/imports and printable strings, then send
    that compact summary to the model. Raw-byte upload is kept
    here for simplicity/hackathon speed.
*/
#define MAX_UPLOAD_BYTES 300000L


/* ================================================================
   RESPONSE BUFFER
   ================================================================ */

typedef struct
{
    char *data;
    size_t size;

} Memory;


/* ================================================================
   CURL WRITE CALLBACK
   ================================================================ */

static size_t write_callback(
    void *contents,
    size_t size,
    size_t nmemb,
    void *userp)
{
    size_t total = size * nmemb;

    Memory *memory =
        (Memory *)userp;

    char *ptr =
        realloc(
            memory->data,
            memory->size + total + 1
        );

    if (ptr == NULL)
    {
        return 0;
    }

    memory->data = ptr;

    memcpy(
        memory->data + memory->size,
        contents,
        total
    );

    memory->size += total;

    memory->data[memory->size] = '\0';

    return total;
}


/* ================================================================
   READ API KEY
   ================================================================ */

const char *get_api_key(void)
{
    const char *key =
        getenv("GEMINI_API_KEY");

    if (key == NULL || strlen(key) == 0)
    {
        fprintf(
            stderr,
            "\n[ERROR] GEMINI_API_KEY is not set.\n"
        );

        fprintf(
            stderr,
            "Set your Gemini API key as an environment variable.\n"
        );

        exit(EXIT_FAILURE);
    }

    return key;
}


/* ================================================================
   GET FILE SIZE
   ================================================================ */

long get_file_size(
    const char *filename)
{
    FILE *fp =
        fopen(filename, "rb");

    if (fp == NULL)
        return -1;

    if (fseek(fp, 0, SEEK_END) != 0)
    {
        fclose(fp);
        return -1;
    }

    long size =
        ftell(fp);

    fclose(fp);

    return size;
}


/* ================================================================
   ESCAPE JSON STRING
   ================================================================ */

char *json_escape(
    const char *input)
{
    if (input == NULL)
        return NULL;

    size_t length = strlen(input);

    /*
        Worst case:
        every character becomes two characters.
    */

    char *output =
        malloc(
            length * 2 + 1
        );

    if (output == NULL)
        return NULL;

    size_t j = 0;

    for (size_t i = 0;
         i < length;
         i++)
    {
        unsigned char c =
            (unsigned char)input[i];

        switch (c)
        {
            case '\"':
                output[j++] = '\\';
                output[j++] = '\"';
                break;

            case '\\':
                output[j++] = '\\';
                output[j++] = '\\';
                break;

            case '\n':
                output[j++] = '\\';
                output[j++] = 'n';
                break;

            case '\r':
                output[j++] = '\\';
                output[j++] = 'r';
                break;

            case '\t':
                output[j++] = '\\';
                output[j++] = 't';
                break;

            default:
                output[j++] = c;
                break;
        }
    }

    output[j] = '\0';

    return output;
}


/* ================================================================
   START RESUMABLE UPLOAD
================================================================ */

char *start_upload(
    const char *filename,
    long file_size,
    const char *api_key)
{
    CURL *curl =
        curl_easy_init();

    if (curl == NULL)
        return NULL;


    Memory response;

    response.data = NULL;
    response.size = 0;


    /*
        Upload metadata request.
    */

    char url[2048];

    snprintf(
        url,
        sizeof(url),
        "%s?key=%s",
        FILE_UPLOAD_ENDPOINT,
        api_key
    );


    /*
        JSON metadata.
    */

    const char *display_name =
        filename;


    char metadata[4096];

    snprintf(
        metadata,
        sizeof(metadata),

        "{"
        "\"file\":{"
        "\"display_name\":\"%s\""
        "}"
        "}",

        display_name
    );


    /*
        Headers required by Gemini Files API.
    */

    struct curl_slist *headers = NULL;

    char length_header[128];

    snprintf(
        length_header,
        sizeof(length_header),
        "X-Goog-Upload-Header-Content-Length: %ld",
        file_size
    );

    headers =
        curl_slist_append(
            headers,
            "Content-Type: application/json"
        );

    headers =
        curl_slist_append(
            headers,
            "X-Goog-Upload-Protocol: resumable"
        );

    headers =
        curl_slist_append(
            headers,
            "X-Goog-Upload-Command: start"
        );

    headers =
        curl_slist_append(
            headers,
            length_header
        );

    headers =
        curl_slist_append(
            headers,
            "X-Goog-Upload-Header-Content-Type: application/octet-stream"
        );


    /*
        Perform request.
    */

    curl_easy_setopt(
        curl,
        CURLOPT_URL,
        url
    );

    curl_easy_setopt(
        curl,
        CURLOPT_HTTPHEADER,
        headers
    );

    curl_easy_setopt(
        curl,
        CURLOPT_POST,
        1L
    );

    curl_easy_setopt(
        curl,
        CURLOPT_POSTFIELDS,
        metadata
    );

    curl_easy_setopt(
        curl,
        CURLOPT_WRITEFUNCTION,
        write_callback
    );

    curl_easy_setopt(
        curl,
        CURLOPT_WRITEDATA,
        &response
    );


    CURLcode result =
        curl_easy_perform(curl);


    /*
        We need response headers because Gemini
        returns the resumable upload URL there.
    */

    curl_slist_free_all(headers);

    curl_easy_cleanup(curl);

    free(response.data);

    /*
        NOTE:

        The upload URL is captured by the dedicated
        header callback below in the actual upload
        function.

        This function is kept separate for clarity.
    */

    if (result != CURLE_OK)
        return NULL;

    return NULL;
}


/* ================================================================
   HEADER BUFFER
================================================================ */

typedef struct
{
    char upload_url[4096];

} HeaderData;


/* ================================================================
   HEADER CALLBACK
================================================================ */

static size_t header_callback(
    char *buffer,
    size_t size,
    size_t nitems,
    void *userdata)
{
    size_t total =
        size * nitems;

    HeaderData *header =
        (HeaderData *)userdata;


    /*
        Header returned by Gemini:

        X-Goog-Upload-URL: https://...
    */

    const char *prefix =
        "X-Goog-Upload-URL:";

    size_t prefix_length =
        strlen(prefix);


    if (total > prefix_length &&
        _strnicmp(
            buffer,
            prefix,
            prefix_length) == 0)
    {
        const char *start =
            buffer + prefix_length;


        while (*start == ' ' ||
               *start == '\t')
        {
            start++;
        }


        size_t length =
            total -
            (start - buffer);


        while (length > 0 &&
              (start[length - 1] == '\r' ||
               start[length - 1] == '\n'))
        {
            length--;
        }


        if (length >=
            sizeof(header->upload_url))
        {
            length =
                sizeof(header->upload_url) - 1;
        }


        memcpy(
            header->upload_url,
            start,
            length
        );

        header->upload_url[length] =
            '\0';
    }


    return total;
}


/* ================================================================
   UPLOAD RAW EXE BYTES
================================================================ */

char *upload_exe(
    const char *filename,
    long file_size,
    long upload_size,
    const char *api_key)
{
    CURL *curl =
        curl_easy_init();

    if (curl == NULL)
        return NULL;


    /*
        ------------------------------------------------------------
        STEP 1:
        START RESUMABLE UPLOAD
        ------------------------------------------------------------

        NOTE: file_size is the TRUE size of the file on disk.
        upload_size is how many bytes we actually send (it may
        be smaller, to stay under Gemini's token limit -- see
        MAX_UPLOAD_BYTES). Gemini's resumable-upload protocol
        needs to know upload_size in advance, since that's the
        exact amount of data that will be streamed.
    */

    char start_url[2048];

    snprintf(
        start_url,
        sizeof(start_url),
        "%s?key=%s",
        FILE_UPLOAD_ENDPOINT,
        api_key
    );


    char metadata[4096];

    snprintf(
        metadata,
        sizeof(metadata),

        "{"
        "\"file\":{"
        "\"display_name\":\"%s\""
        "}"
        "}",

        filename
    );


    struct curl_slist *headers = NULL;

    char length_header[128];

    snprintf(
        length_header,
        sizeof(length_header),
        "X-Goog-Upload-Header-Content-Length: %ld",
        upload_size
    );


    headers =
        curl_slist_append(
            headers,
            "Content-Type: application/json"
        );

    headers =
        curl_slist_append(
            headers,
            "X-Goog-Upload-Protocol: resumable"
        );

    headers =
        curl_slist_append(
            headers,
            "X-Goog-Upload-Command: start"
        );

    headers =
        curl_slist_append(
            headers,
            length_header
        );

    headers =
        curl_slist_append(
            headers,
            "X-Goog-Upload-Header-Content-Type: application/octet-stream"
        );


    HeaderData header_data;

    memset(
        &header_data,
        0,
        sizeof(header_data)
    );


    Memory response;

    response.data = NULL;
    response.size = 0;


    curl_easy_setopt(
        curl,
        CURLOPT_URL,
        start_url
    );

    curl_easy_setopt(
        curl,
        CURLOPT_HTTPHEADER,
        headers
    );

    curl_easy_setopt(
        curl,
        CURLOPT_POST,
        1L
    );

    curl_easy_setopt(
        curl,
        CURLOPT_POSTFIELDS,
        metadata
    );

    curl_easy_setopt(
        curl,
        CURLOPT_HEADERFUNCTION,
        header_callback
    );

    curl_easy_setopt(
        curl,
        CURLOPT_HEADERDATA,
        &header_data
    );

    curl_easy_setopt(
        curl,
        CURLOPT_WRITEFUNCTION,
        write_callback
    );

    curl_easy_setopt(
        curl,
        CURLOPT_WRITEDATA,
        &response
    );


    CURLcode result =
        curl_easy_perform(curl);


    curl_slist_free_all(headers);

    free(response.data);


    if (result != CURLE_OK)
    {
        fprintf(
            stderr,
            "[ERROR] Could not initialize upload: %s\n",
            curl_easy_strerror(result)
        );

        curl_easy_cleanup(curl);

        return NULL;
    }


    if (strlen(header_data.upload_url) == 0)
    {
        fprintf(
            stderr,
            "[ERROR] Gemini did not return upload URL.\n"
        );

        curl_easy_cleanup(curl);

        return NULL;
    }


    printf(
        "[+] Resumable upload initialized.\n"
    );


    /*
        ------------------------------------------------------------
        STEP 2:
        SEND RAW EXE BYTES
        ------------------------------------------------------------
    */

    FILE *fp =
        fopen(filename, "rb");

    if (fp == NULL)
    {
        curl_easy_cleanup(curl);
        return NULL;
    }


    /*
        Read only the first upload_size bytes of the EXE into
        memory (may be the whole file, or a capped prefix --
        see MAX_UPLOAD_BYTES).

        For a hackathon this is simple.

        For very large samples, implement chunked upload.
    */

    unsigned char *data =
        malloc(
            (size_t)upload_size
        );

    if (data == NULL)
    {
        fclose(fp);
        curl_easy_cleanup(curl);
        return NULL;
    }


    size_t bytes_read =
        fread(
            data,
            1,
            (size_t)upload_size,
            fp
        );


    fclose(fp);


    if (bytes_read !=
        (size_t)upload_size)
    {
        fprintf(
            stderr,
            "[ERROR] Could not read expected number of bytes "
            "from EXE.\n"
        );

        free(data);

        curl_easy_cleanup(curl);

        return NULL;
    }


    struct curl_slist *upload_headers =
        NULL;


    char content_length[128];

    snprintf(
        content_length,
        sizeof(content_length),
        "Content-Length: %ld",
        upload_size
    );


    upload_headers =
        curl_slist_append(
            upload_headers,
            content_length
        );

    upload_headers =
        curl_slist_append(
            upload_headers,
            "X-Goog-Upload-Offset: 0"
        );

    upload_headers =
        curl_slist_append(
            upload_headers,
            "X-Goog-Upload-Command: upload, finalize"
        );


    Memory upload_response;

    upload_response.data = NULL;
    upload_response.size = 0;


    curl_easy_setopt(
        curl,
        CURLOPT_URL,
        header_data.upload_url
    );

    curl_easy_setopt(
        curl,
        CURLOPT_HTTPHEADER,
        upload_headers
    );

    curl_easy_setopt(
        curl,
        CURLOPT_POST,
        1L
    );

    curl_easy_setopt(
        curl,
        CURLOPT_POSTFIELDS,
        data
    );

    curl_easy_setopt(
        curl,
        CURLOPT_POSTFIELDSIZE,
        (long)upload_size
    );

    curl_easy_setopt(
        curl,
        CURLOPT_WRITEFUNCTION,
        write_callback
    );

    curl_easy_setopt(
        curl,
        CURLOPT_WRITEDATA,
        &upload_response
    );


    result =
        curl_easy_perform(curl);


    free(data);

    curl_slist_free_all(upload_headers);

    curl_easy_cleanup(curl);


    if (result != CURLE_OK)
    {
        fprintf(
            stderr,
            "[ERROR] Raw binary upload failed: %s\n",
            curl_easy_strerror(result)
        );

        free(upload_response.data);

        return NULL;
    }


    printf(
        "[+] Raw EXE bytes uploaded successfully.\n"
    );


    /*
        Return Gemini's file information JSON.
    */

    return upload_response.data;
}


/* ================================================================
   EXTRACT FILE URI
================================================================ */

char *extract_file_uri(
    const char *json)
{
    const char *search =
        "\"uri\"";

    const char *position =
        strstr(
            json,
            search
        );


    if (position == NULL)
        return NULL;


    position =
        strchr(
            position,
            ':'
        );


    if (position == NULL)
        return NULL;


    position++;


    while (*position == ' ' ||
           *position == '\t' ||
           *position == '\"')
    {
        position++;
    }


    const char *end =
        strchr(
            position,
            '\"'
        );


    if (end == NULL)
        return NULL;


    size_t length =
        (size_t)(end - position);


    char *uri =
        malloc(
            length + 1
        );


    if (uri == NULL)
        return NULL;


    memcpy(
        uri,
        position,
        length
    );


    uri[length] =
        '\0';


    return uri;
}


/* ================================================================
   BUILD AI PROMPT
================================================================ */

const char *analysis_prompt =
"You are an AI-assisted defensive malware-analysis engine. "
"\n\n"
"The attached file is a Windows executable. "
"\n"
"NOTE: to stay within the model's input token limit, the "
"uploaded data may be a TRUNCATED PREFIX of the full file "
"rather than the complete binary. Do not assume anything "
"about sections or data beyond what was actually provided, "
"and call out clearly where your analysis is limited by this. "
"\n"
"Perform STATIC ANALYSIS ONLY. "
"\n"
"DO NOT execute the executable. "
"\n\n"

"Your task is to analyze the raw executable and attempt "
"to understand and reconstruct its behavior. "
"\n\n"

"IMPORTANT: "
"If the original source code cannot be reliably recovered, "
"do NOT invent source code. Instead provide the closest "
"reliable representation such as assembly interpretation, "
"pseudocode, control-flow explanation, or behavioral description. "
"\n\n"

"Analyze the following: "
"\n\n"

"1. PE structure and architecture. "
"\n"
"2. Entry point and important sections. "
"\n"
"3. Evidence of packing or compression. "
"\n"
"4. Evidence of encryption or encoded data. "
"\n"
"5. Obfuscation techniques. "
"\n"
"6. Suspicious imports and API capabilities. "
"\n"
"7. Embedded strings and resources if observable. "
"\n"
"8. Network-related behavior. "
"\n"
"9. Process and memory manipulation. "
"\n"
"10. Persistence-related behavior. "
"\n"
"11. Credential or sensitive-data access indicators. "
"\n"
"12. File-system and registry behavior indicators. "
"\n"
"13. Attempt to reconstruct readable pseudocode for "
"important functions when possible. "
"\n"
"14. Explain what the executable appears to be doing. "
"\n"
"15. Distinguish OBSERVED evidence from INFERENCE. "
"\n"
"16. Identify uncertainty and limitations. "
"\n"
"17. Give an EDR MALWARE RISK SCORE from 0 to 100. "
"\n"
"18. Give a separate CONFIDENCE score from 0 to 100. "
"\n\n"

"Do not claim that a file is malware solely because it is "
"packed, has high entropy, or uses APIs that can also be "
"used by legitimate software. "
"\n\n"

"Return the result using this structure: "
"\n\n"

"=== FILE SUMMARY ===\n"
"=== ARCHITECTURE ===\n"
"=== OBFUSCATION / PACKING ===\n"
"=== DEOBFUSCATED / RECONSTRUCTED LOGIC ===\n"
"=== OBSERVED BEHAVIOR ===\n"
"=== SUSPICIOUS INDICATORS ===\n"
"=== EVIDENCE ===\n"
"=== UNCERTAINTIES ===\n"
"=== EDR RISK SCORE ===\n"
"=== CONFIDENCE ===\n"
"=== FINAL ASSESSMENT ===\n";


/* ================================================================
   SEND FILE TO GEMINI
================================================================ */

char *analyze_with_gemini(
    const char *file_uri,
    const char *api_key)
{
    CURL *curl =
        curl_easy_init();

    if (curl == NULL)
        return NULL;


    Memory response;

    response.data = NULL;
    response.size = 0;


    /*
        ------------------------------------------------------------
        Build generateContent URL
        ------------------------------------------------------------
    */

    char url[2048];

    snprintf(
        url,
        sizeof(url),
        "%s?key=%s",
        GENERATE_ENDPOINT,
        api_key
    );


    /*
        ------------------------------------------------------------
        Escape prompt + URI
        ------------------------------------------------------------
    */

    char *escaped_prompt =
        json_escape(
            analysis_prompt
        );


    char *escaped_uri =
        json_escape(
            file_uri
        );


    if (!escaped_prompt ||
        !escaped_uri)
    {
        free(escaped_prompt);
        free(escaped_uri);

        curl_easy_cleanup(curl);

        return NULL;
    }


    /*
        ------------------------------------------------------------
        JSON request
        ------------------------------------------------------------

        The important part is:

        file_data
            |
            +-- mime_type
            +-- file_uri

        Gemini receives the uploaded EXE reference.
    */

    size_t json_size =
        strlen(escaped_prompt) +
        strlen(escaped_uri) +
        2048;


    char *json =
        malloc(json_size);


    if (json == NULL)
    {
        free(escaped_prompt);
        free(escaped_uri);

        curl_easy_cleanup(curl);

        return NULL;
    }


    snprintf(
        json,
        json_size,

        "{"
        "\"contents\":["
        "{"
        "\"parts\":["
        "{"
        "\"text\":\"%s\""
        "},"
        "{"
        "\"file_data\":{"
        "\"mime_type\":\"application/octet-stream\","
        "\"file_uri\":\"%s\""
        "}"
        "}"
        "]"
        "}"
        "]"
        "}",

        escaped_prompt,
        escaped_uri
    );


    free(escaped_prompt);
    free(escaped_uri);


    /*
        ------------------------------------------------------------
        Headers
        ------------------------------------------------------------
    */

    struct curl_slist *headers =
        NULL;


    headers =
        curl_slist_append(
            headers,
            "Content-Type: application/json"
        );


    /*
        ------------------------------------------------------------
        POST request
        ------------------------------------------------------------
    */

    curl_easy_setopt(
        curl,
        CURLOPT_URL,
        url
    );

    curl_easy_setopt(
        curl,
        CURLOPT_HTTPHEADER,
        headers
    );

    curl_easy_setopt(
        curl,
        CURLOPT_POST,
        1L
    );

    curl_easy_setopt(
        curl,
        CURLOPT_POSTFIELDS,
        json
    );

    curl_easy_setopt(
        curl,
        CURLOPT_WRITEFUNCTION,
        write_callback
    );

    curl_easy_setopt(
        curl,
        CURLOPT_WRITEDATA,
        &response
    );


    CURLcode result =
        curl_easy_perform(curl);


    free(json);

    curl_slist_free_all(headers);

    curl_easy_cleanup(curl);


    if (result != CURLE_OK)
    {
        fprintf(
            stderr,
            "[ERROR] Gemini API request failed: %s\n",
            curl_easy_strerror(result)
        );

        free(response.data);

        return NULL;
    }


    return response.data;
}


/* ================================================================
   EXTRACT AI TEXT FROM RESPONSE
================================================================ */

char *extract_ai_text(
    const char *json)
{
    /*
        Gemini response generally contains:

        candidates
          -> content
             -> parts
                -> text

        This lightweight extractor is for the hackathon
        prototype.

        For production, replace this with a real JSON
        parser such as cJSON.
    */

    const char *search =
        "\"text\"";


    const char *position =
        strstr(
            json,
            search
        );


    if (position == NULL)
        return NULL;


    position =
        strchr(
            position,
            ':'
        );


    if (position == NULL)
        return NULL;


    position++;


    while (*position == ' ' ||
           *position == '\t' ||
           *position == '\"')
    {
        position++;
    }


    const char *end =
        position;


    while (*end)
    {
        if (*end == '\"' &&
            *(end - 1) != '\\')
        {
            break;
        }

        end++;
    }


    size_t length =
        (size_t)(end - position);


    char *result =
        malloc(
            length + 1
        );


    if (result == NULL)
        return NULL;


    memcpy(
        result,
        position,
        length
    );


    result[length] =
        '\0';


    return result;
}


/* ================================================================
   SAVE RESULT
================================================================ */

int save_result(
    const char *filename,
    const char *response)
{
    FILE *fp =
        fopen(
            filename,
            "w"
        );


    if (fp == NULL)
        return 0;


    fprintf(
        fp,
        "%s",
        response
    );


    fclose(fp);


    return 1;
}


/* ================================================================
   MAIN
================================================================ */

int main(
    int argc,
    char **argv)
{
    printf(
        "\n"
        "============================================================\n"
        "        AI-POWERED EXE STATIC ANALYZER\n"
        "============================================================\n"
    );


    /*
        ------------------------------------------------------------
        Command-line argument
        ------------------------------------------------------------
    */

    if (argc != 2 && argc != 3)
    {
        printf(
            "\nUsage:\n"
            "    analyzer <sample.exe> [max_upload_bytes]\n\n"
            "    max_upload_bytes (optional) overrides the default\n"
            "    cap of %ld bytes sent to Gemini, to avoid exceeding\n"
            "    its token limit on large files.\n\n",
            MAX_UPLOAD_BYTES
        );

        return EXIT_FAILURE;
    }


    const char *filename =
        argv[1];


    long max_upload_bytes =
        MAX_UPLOAD_BYTES;

    if (argc == 3)
    {
        long override =
            atol(argv[2]);

        if (override > 0)
        {
            max_upload_bytes = override;
        }
        else
        {
            fprintf(
                stderr,
                "[WARN] Invalid max_upload_bytes argument, "
                "using default (%ld).\n",
                MAX_UPLOAD_BYTES
            );
        }
    }


    /*
        ------------------------------------------------------------
        Check file
        ------------------------------------------------------------
    */

    long file_size =
        get_file_size(
            filename
        );


    if (file_size < 0)
    {
        fprintf(
            stderr,
            "\n[ERROR] Cannot open file:\n%s\n",
            filename
        );

        return EXIT_FAILURE;
    }


    printf(
        "\nTarget : %s",
        filename
    );

    printf(
        "\nSize   : %ld bytes\n",
        file_size
    );


    long upload_size =
        file_size;

    if (upload_size > max_upload_bytes)
    {
        upload_size = max_upload_bytes;

        printf(
            "\n[WARN] File exceeds %ld byte upload cap.\n"
            "       Only the first %ld bytes will be sent to "
            "Gemini to stay under its token limit.\n"
            "       Increase the cap with a third CLI argument "
            "if you need to inspect more of the file, e.g.:\n"
            "           %s %s %ld\n",
            max_upload_bytes,
            upload_size,
            argv[0],
            filename,
            file_size
        );
    }


    /*
        ------------------------------------------------------------
        API key
        ------------------------------------------------------------
    */

    const char *api_key =
        get_api_key();


    /*
        ------------------------------------------------------------
        Initialize libcurl
        ------------------------------------------------------------
    */

    curl_global_init(
        CURL_GLOBAL_DEFAULT
    );


    /*
        ------------------------------------------------------------
        STEP 1
        Upload raw EXE
        ------------------------------------------------------------
    */

    printf(
        "\n[1/3] Uploading RAW EXE bytes to Gemini...\n"
    );


    char *file_info =
        upload_exe(
            filename,
            file_size,
            upload_size,
            api_key
        );


    if (file_info == NULL)
    {
        fprintf(
            stderr,
            "[ERROR] Upload failed.\n"
        );

        curl_global_cleanup();

        return EXIT_FAILURE;
    }


    /*
        Save upload response for debugging.
    */

    save_result(
        "upload_response.json",
        file_info
    );


    printf(
        "[+] Upload response saved to "
        "upload_response.json\n"
    );


    /*
        ------------------------------------------------------------
        STEP 2
        Extract Gemini file URI
        ------------------------------------------------------------
    */

    char *file_uri =
        extract_file_uri(
            file_info
        );


    if (file_uri == NULL)
    {
        fprintf(
            stderr,
            "\n[ERROR] Could not extract Gemini file URI.\n"
        );

        fprintf(
            stderr,
            "Check upload_response.json\n"
        );


        free(file_info);

        curl_global_cleanup();

        return EXIT_FAILURE;
    }


    printf(
        "[+] Gemini file URI obtained.\n"
    );


    /*
        ------------------------------------------------------------
        STEP 3
        Send uploaded raw binary to Gemini
        ------------------------------------------------------------
    */

    printf(
        "\n[2/3] Sending executable to AI analyzer...\n"
    );


    char *gemini_response =
        analyze_with_gemini(
            file_uri,
            api_key
        );


    if (gemini_response == NULL)
    {
        fprintf(
            stderr,
            "[ERROR] Gemini analysis failed.\n"
        );


        free(file_uri);
        free(file_info);

        curl_global_cleanup();

        return EXIT_FAILURE;
    }


    /*
        Save COMPLETE JSON response.
    */

    if (save_result(
            "gemini_result.json",
            gemini_response))
    {
        printf(
            "[+] Complete Gemini response saved to "
            "gemini_result.json\n"
        );
    }


    /*
        ------------------------------------------------------------
        Extract readable AI text
        ------------------------------------------------------------
    */

    char *ai_text =
        extract_ai_text(
            gemini_response
        );


    printf(
        "\n[3/3] AI ANALYSIS COMPLETE\n"
    );


    printf(
        "\n"
        "============================================================\n"
        "                    GEMINI RESULT\n"
        "============================================================\n\n"
    );


    if (ai_text != NULL)
    {
        printf(
            "%s\n",
            ai_text
        );

        free(ai_text);
    }
    else
    {
        /*
            If extraction fails, print raw JSON.
        */

        printf(
            "%s\n",
            gemini_response
        );
    }


    printf(
        "\n============================================================\n"
    );


    /*
        Cleanup
    */

    free(
        gemini_response
    );

    free(
        file_uri
    );

    free(
        file_info
    );


    curl_global_cleanup();


    printf(
        "\nDone.\n"
    );


    return EXIT_SUCCESS;
}