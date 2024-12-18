#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <getopt.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <pthread.h>
#include <crypt.h>
#include <fcntl.h>
#include <string.h>
#include "thread_hash.h"

#ifndef DEFAULT_NUM_THREADS
# define DEFAULT_NUM_THREADS 1
#endif

#ifndef MAX_NUM_THREADS
# define MAX_NUM_THREADS 24
#endif

char ** read_from_file(char * file_name, int * num_words);
char ** parse_text(char * buf, int num_words);
void free_text(char ** text, int num_words);

void thread_decrypt(void);
void * decrypt(void * vid);
void identify_hash_algorithm(char * password, int algorithm_count[]);

void display_stats(int * algorithm_count, double total_time, int password_count, int failed_decrypts);
int get_next_row(void);
double elapse_time(struct timeval * t0, struct timeval * t1);

static int is_verbose = 0;
static int output_fd = STDOUT_FILENO;
static char ** passwords = NULL;
static char ** keys = NULL;

static int num_passwords =  0;
static int num_keys = 0;

static int total_algorithm_count[ALGORITHM_MAX] = {0};
static int total_failed_decrypts = 0;

int main(int argc, char * argv[])
{
   int opt = -1;
   char * password_file = NULL;
   char * dict_file = NULL;
   char * output_file = NULL;
 
   struct timeval et0;
   struct timeval et1;

   int num_threads = DEFAULT_NUM_THREADS;
   
   pthread_t * threads = NULL;

   long tid = 0;

   double total_time = 0.0;

   while ((opt = getopt(argc, argv, OPTIONS)) != -1) 
   {
       switch (opt)
       {
		   case 'i':
		       password_file = optarg;
		       break;

		   case 'o':
		       output_file = optarg;
			   break;

		   case 'd':
		       dict_file = optarg;
			   break;

           case 't':
               num_threads = atoi(optarg);

			   if (num_threads < DEFAULT_NUM_THREADS || num_threads > MAX_NUM_THREADS)
			   {
			       fprintf(stderr, "invalid thread count %d\n", num_threads);
				   exit(EXIT_FAILURE);
			   }
               break;

           case 'v':
		       is_verbose = 1;
			   fprintf(stderr, "Verbose mode: enabled\n");
               break;

           case 'h':
		       printf("\nhelp text "
			          "\n\t%s ..."
					  "\n\tOptions: %s"
					  "\n\t\t-i file\t\thash file name (required)"
					  "\n\t\t-o file\t\toutput file name (default stdout)"
					  "\n\t\t-d file\t\tdictionary file name (default stdout)"
					  "\n\t\t-t #\t\tnumber of threads to create (default 1)"
					  "\n\t\t-v\t\tenable verbose mode"
					  "\n\t\t-h\t\thelpful text\n", argv[0], OPTIONS
			         );
               break;

		   case 'n':
		       nice(NICE_VALUE);
			   break;
              
           default: 
		       fprintf(stderr, "oopsie - unrecognized command line option \"%s\"\n", argv[optind]);
               break;
        }
   }

   gettimeofday(&et0, NULL);   

   if (!dict_file)
   {
       fprintf(stderr, "must give name for dictionary input file with -d filename\n");
	   exit(EXIT_FAILURE);
   }

   if (!password_file)
   {
       fprintf(stderr, "must give name for hashed password input file with -i filename\n");
	   exit(EXIT_FAILURE);
   }

   passwords = read_from_file(password_file, &num_passwords);
   keys = read_from_file(dict_file, &num_keys);

   //Opens a file for writing.
   if (output_file)
	   output_fd = open(output_file, O_WRONLY | O_TRUNC | O_CREAT, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);

   if (output_fd < 0)
   {
       fprintf(stderr, "Could not open output file\n");
   }

   memset(total_algorithm_count, 0, ALGORITHM_MAX * sizeof(int));
 
   threads = malloc(num_threads * sizeof(pthread_t));
    
   for (tid = 0; tid < num_threads; ++tid)
   {
       pthread_create(&threads[tid], NULL, decrypt, (void *) tid);
   } 

   for (tid = 0; tid < num_threads; ++tid)
   {
       pthread_join(threads[tid], NULL);
   }
 
   gettimeofday(&et1, NULL);   

   total_time = elapse_time(&et0, &et1);

   fprintf(stderr, "total: %3d %8.2lf sec", num_threads, total_time);

   display_stats(total_algorithm_count, total_time, num_passwords, total_failed_decrypts);

   free(threads);

   if (passwords)
   {
	   //Deallocates the list of passwords.
	   free_text(passwords, num_passwords);
	   free(passwords);
       passwords = NULL;
   }

   if (keys)
   {
	   //Deallocates the list of keys.
	   free_text(keys, num_keys);
	   free(keys);
       keys = NULL;
   }

   if (output_fd > -1)
	   close(output_fd);

   pthread_exit(EXIT_SUCCESS);
}

char ** read_from_file(char * file_name, int * num_words)
{
   int input_fd = -1;
   char ** text = NULL;
   char * buf = NULL;
   struct stat md;

   *num_words = 0;

   if (!file_name)
   {
	   fprintf(stderr, "\nNo input file specified.");
       return 0;
   }

   //Opens the specified file in read-only mode.
   input_fd = open(file_name, O_RDONLY);
   
   if (input_fd < 0)
   {
       fprintf(stderr, "failed to open input file\n");
       return 0;
   }

   memset(&md, 0, sizeof(struct stat));

   //Retrieving the metadata of the file.
   fstat(input_fd, &md);

   //Creates a dynamic array precisely set to the size of
   //the file plus one.
   buf = (char *) malloc((md.st_size + 1) * sizeof(char));

   //Reading in the contents of the file into the buffer.
   if (read(input_fd, buf, md.st_size) < 1)
   {
       fprintf(stderr, "\nCould not read from %s\n", file_name);
   }

   //Obtains the number of words in the file by counting the
   //number of newline characters that was read into the
   //buffer.
   for (int i = 0; i < md.st_size; ++i)
   {
	   if (buf[i] == '\n')
		   ++(*num_words);
   }

   text = parse_text(buf, *num_words);

   //Deallocates the buffer
   if (buf)
   {
       free(buf);
	   buf = NULL;
   }

   return text;
}

char ** parse_text(char * buf, int num_words)
{
   //Creates an dynamic array of strings precisely sized to
   //hold all newline-delimited words in the buffer.
   char ** text = (char **) malloc(num_words * sizeof(char *));
   memset(text, 0, num_words * sizeof(char *));

   //Makes a duplicate of the first newline-delimited word 
   //in the buffer and stores it into the first element
   //of text.
   text[0] = strdup(strtok(buf, "\n"));

   //Stores the remaining newline-delimited words in the
   //buffer into text.
   for (int i = 1; i < num_words; ++i)
   {
       text[i] = strdup(strtok(NULL, "\n"));
   }

   return text;
}

void free_text(char ** text, int num_words)
{
   //Deallocates the array of strings.
   for (int i = 0; i < num_words; ++i)
   {
      if (text[i])
      {
		  free(text[i]);
		  text[i] = NULL;
	  }
   }

   return;
}


void * decrypt(void * vid)
{
   char *password = NULL;
   struct crypt_data crypt_data;
   int is_match = 0;
   char * buf = NULL;   
   int buf_length = 0;
   int algorithm_count_per_thread[ALGORITHM_MAX] = {0};
   int failed_decrypts = 0;
   int password_count = 0;

   struct timeval et0;
   struct timeval et1;
   double total_time = 0.0;

   static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
   long thread_num = (long) vid;

   //Obtains the time just before the thread begins processing the password 
   //and dictionary word lists.
   gettimeofday(&et0, NULL);   

   //Iterates through the array of strings containing the passwords 
   //read in from a password text file.
   for (int i = get_next_row(); i < num_passwords; i = get_next_row())
   { 
       //pthread_mutex_lock(&lock);
	   identify_hash_algorithm(passwords[i], algorithm_count_per_thread);    
       //pthread_mutex_unlock(&lock);

       memset(&crypt_data, 0, sizeof(crypt_data));
       strncpy(crypt_data.setting, passwords[i], CRYPT_OUTPUT_SIZE);

       //Iterates through the array of strings containing the dictionary words 
	   //read in from a plain text file.
	   for (int j = 0; j < num_keys && !is_match; ++j)
	   {
           strncpy(crypt_data.input, keys[j], CRYPT_MAX_PASSPHRASE_SIZE);

           //Converts the current word into a hashed phrase.
           password = crypt_rn(keys[j], passwords[i], &crypt_data, sizeof(crypt_data));
      
	       //Checks if the hashed phrase matches any of the passwords read in
		   //from the password text file.
           if (strcmp(crypt_data.setting, password) == 0) 
	       {
			   //Calculates the appropriate length for the buf.
               buf_length = strlen("cracked  %s  %s\n") + strlen(crypt_data.input) + strlen(crypt_data.output) + 1;
			   buf = (char *) calloc(buf_length, sizeof(char));

               //Appends the text into buf.
               sprintf(buf, "cracked  %s  %s\n", crypt_data.input, crypt_data.output);

               //Writes the error message to either stdout or an output file.
		       write(output_fd, buf, strlen(buf));

			   is_match = 1;
			   free(buf);
           }
	   }

       if (!is_match)
	   {
		   //Calculates the appropriate length for the buf.
           buf_length = strlen("*** failed to crack  %s\n") + strlen(crypt_data.setting) + 1;
		   buf = (char *) calloc(buf_length, sizeof(char));
          
           //Appends the text into buf.
		   sprintf(buf, "*** failed to crack  %s\n", crypt_data.setting);

           //Writes the error message to either stdout or an output file.
		   write(output_fd, buf, strlen(buf));

           pthread_mutex_lock(&lock);
		   ++total_failed_decrypts;
           pthread_mutex_unlock(&lock);

		   ++failed_decrypts;
		   free(buf);
	   }

	   is_match = 0;
	   ++password_count;
   }

   //Obtains the time once the thread has completed processing the password 
   //and dictionary word lists.
   gettimeofday(&et1, NULL);   

   total_time = elapse_time(&et0, &et1);
 
   fprintf(stderr, "thread: %2ld %8.2lf sec", thread_num, total_time);
   display_stats(algorithm_count_per_thread, total_time, password_count, failed_decrypts);

   pthread_exit(EXIT_SUCCESS);
}

void identify_hash_algorithm(char * password, int algorithm_count_per_thread[])
{
   static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
   hash_algorithm_t algorithm_used;
   if (!password)
	   return;

   //Checks if the password was created using the 
   //data encryption standard (DES) algorithm.
   if (password[0] != '$')
   {
	   algorithm_used = DES;
   }
 
   //Checks if the password was created using the 
   //NT algorithm.
   else if (password[1] == '3')
   { 
	   algorithm_used = NT;
   }

   //Checks if the password was created using the 
   //md5 algorithm.
   else if (password[1] == '1')
   {
	   algorithm_used = MD5;
   }

   //Checks if the password was created using the 
   //sha256 algorithm.
   else if (password[1] == '5')
   {
	   algorithm_used = SHA256;
   }

   //Checks if the password was created using the 
   //sha512 algorithm.
   else if (password[1] == '6')
   {
	   algorithm_used = SHA512;
   }

   //Checks if the password was created using the 
   //yescrypt algorithm.
   else if (password[1] == 'y')
   {
	   algorithm_used = YESCRYPT;
   }

   //Checks if the password was created using the 
   //gost-yescrypt algorithm.
   else if (password[1] == 'g' && password[2] == 'y')
   {
	   algorithm_used = GOST_YESCRYPT;
   }

   //Checks if the password was created using the 
   //becrypt algorithm.
   else if (password[1] == '2' && password[2] == 'b')
   {
	   algorithm_used = BCRYPT;
   }


   pthread_mutex_lock(&lock);
   //Updates the table (global variable) managing the total 
   //count of each encryption algorithm for the entire program.
   total_algorithm_count[algorithm_used] += 1;             
   pthread_mutex_unlock(&lock);

   //Updates the table managing the total count of each
   //encryption algorithm for the calling thread.
   algorithm_count_per_thread[algorithm_used] += 1;   

   return;
}

void display_stats(int * algorithm_count, double total_time, int password_count, int failed_decrypts)
{
   //Displays the names of the relevant encryption algorithms and the number of times
   //each algorithm was used.
   for (hash_algorithm_t i = DES; i < ALGORITHM_MAX; ++i)
   {
        fprintf(stderr, "%17s: %5d", algorithm_string[i], algorithm_count[i]);
   }

   //Displays the total number of passwords processed and unsuccessful decryptions.
   fprintf(stderr, "  total: %8d  failed: %8d\n", password_count, failed_decrypts);

   return;
}

double elapse_time(struct timeval * t0, struct timeval * t1)
{
   return (((double) (t1->tv_usec - t0->tv_usec)) / MICROSECONDS_PER_SECOND) + ((double) (t1->tv_sec - t0->tv_sec));
}


int get_next_row(void)
{
   static int next_row = 0;
   static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
   int cur_row = 0;

   //CRITICAL SECTION: Locking the mutex here ensures only a single thread 
   //can increment next_row at any given time.
   pthread_mutex_lock(&lock);

   cur_row = next_row++;

   pthread_mutex_unlock(&lock);

   //Returns the row index of the element the calling thread may process next.
   return cur_row;
}

