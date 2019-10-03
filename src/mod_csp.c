/*Content Security Policy Nonce Support*/
#include "httpd.h"
#include "http_config.h"
#include "apr_buckets.h"
#include "util_filter.h"
#include "apr_strings.h"
#include "http_log.h"
#include <regex.h>

#define MAX_NONCE_LEN 27
#define CSP_HEADER "Content-Security-Policy"
#define NONCE_DIRECTIVE "script-nonce %s"

static const char module_name[] = "csp";
module AP_MODULE_DECLARE_DATA csp_module;


char* get_nonce(ap_filter_t *);
char* replace_nonce(ap_filter_t *, const char*,const char*, const char*);

typedef struct csp_cfg {
  const char *key;
} csp_cfg;


/*main function to support CSP*/
static apr_status_t csp_filter(ap_filter_t *f, apr_bucket_brigade *bb) {
  char *nonce;
  csp_cfg* cfg = ap_get_module_config(f->r->per_dir_config, &csp_module);
  
  const char *ret = NULL;
  char *nonce_directive = NULL;
  apr_size_t len;
  apr_status_t rv;
  char *buf;
  apr_bucket_brigade *bbout;
  apr_bucket *b;
  int sret=0;
  char *newbuf;

  ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, f->r,
		"cfg->key=%s", cfg->key);
  
  ret = apr_table_get(f->r->headers_out, CSP_HEADER);
  ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, f->r,
		"table_get:return%d",(int) ret);
    
  if(ret) {
    //nonce is in header
    ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, f->r,
		  "had header:%s\n", ret);
    sret = sscanf(ret, NONCE_DIRECTIVE, nonce);
    if(sret != 1) {
      ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, f->r,
		       "Error sscanf");
      return HTTP_INTERNAL_SERVER_ERROR;
    }
  }else {
    
    //get a new nonce
    ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, f->r,
		  "getting_nonce..");
    
    nonce = get_nonce(f);
    ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, f->r,
		  "get_nonce:%s", nonce);
    
    
    len = strlen(NONCE_DIRECTIVE) + MAX_NONCE_LEN + 1;
    nonce_directive = apr_palloc(f->r->pool, len);
   
    snprintf(nonce_directive, len, NONCE_DIRECTIVE, nonce); 
    
    ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, f->r,
		  "set header:%s", nonce_directive);
    
    apr_table_set(f->r->headers_out, CSP_HEADER, nonce_directive);

    
  }
  
  rv = apr_brigade_pflatten(bb, &buf, &len, f->r->pool);
  if (rv != APR_SUCCESS) {
    ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, f->r,
		  "Error (flatten) reading form data");
    return HTTP_INTERNAL_SERVER_ERROR;
  }
  /*zero out*/
  buf[len] = 0;  
  ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, f->r,
		"buf=%s", buf);
  
  newbuf = replace_nonce(f, buf, nonce, cfg->key);

  ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, f->r,
		"newbuf=%s", newbuf);
    
  b = apr_bucket_pool_create(newbuf, strlen(newbuf), f->r->pool, 
			     f->r->connection->bucket_alloc);
  if(!b) {
    ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, f->r,
		  "Error apr_bucket_pool_create");
    return HTTP_INTERNAL_SERVER_ERROR;
  }

  bbout = apr_brigade_create(f->r->pool, f->r->connection->bucket_alloc);
  APR_BRIGADE_INSERT_TAIL(bbout, b);
  APR_BRIGADE_INSERT_TAIL(bbout,
			  apr_bucket_eos_create(bbout->bucket_alloc));
  return ap_pass_brigade(f->next, bbout);
  
}

/*register module hooks*/
static void register_hooks(apr_pool_t *p) {
  srand((int)time(0));
  ap_register_output_filter(module_name, csp_filter, NULL,
			    AP_FTYPE_CONTENT_SET);
}

/*passed as param in csp_cmds*/
static const char* csp_set_key(cmd_parms* cmd, void* cfg, const char* val) {
  ((csp_cfg *)cfg)->key = val;
  return NULL;
}

/*process command directives*/
static const command_rec csp_cmds[] = {
  AP_INIT_TAKE1("SetCSPKey", csp_set_key, NULL, OR_ALL,
		"Key for CSP Nonce"),
  {NULL}  /*why use brackets?*/
};


/*alloc memeory for csp_cfg*/
static void* create_csp_cfg(apr_pool_t* pool, char* x) {
  csp_cfg* cfg = apr_pcalloc(pool, sizeof(csp_cfg));
  return cfg;
}

module AP_MODULE_DECLARE_DATA csp_module = {
  STANDARD20_MODULE_STUFF,
  create_csp_cfg,   /*create per-dir config*/
  NULL,   /*merge per-dir config*/
  NULL,   /*create per-host config*/
  NULL,   /*merge per-host config*/
  csp_cmds,   /*command directives for this module*/
  register_hooks
};
  



char *replace_nonce(ap_filter_t *f, const char *buf,const char *nonce,const char *key)
{
    //regex
    regex_t reg_key;
    regex_t reg;
    int reti;
    int sec_reti;
    int buf_len;
    regmatch_t pmatch[1];
        
    //parameters set myself
    char *const_regex = "<[ \f\n\r\t\v]*script[ \f\n\r\t\vA-Za-z0-9_=\"./'@#$!~^&*()%%\\]*nonce[ \f\n\r\t\v]*=[ \f\n\r\t\v]*\"key";
    char *regular_expression = NULL;
    const char *p, *q; //used as a pointer to locate the matching place
    char *w; // used in matching place
    int i = 0; //use to count matching time
    int j;
    //int Number_so[50]; //store the location of key in each time loop
    int *Number_eo;
    //int Nonce_Starting_Location[50];
    int *Nonce_Ending_Location;
    char *new_buf = NULL;
    
    buf_len = strlen(buf);
    //put $key int const_regex by regular expression -> then use regular_expression to do regex
    reti = regcomp(&reg_key, "key", 0);
    reti = regexec(&reg_key, const_regex, 1, pmatch, 0);
    
    regular_expression = apr_palloc(f->r->pool, strlen(const_regex) + strlen(key));
    memset(regular_expression, 0, strlen(const_regex) + strlen(key));
    memcpy(regular_expression, const_regex, pmatch[0].rm_so);
    memcpy(regular_expression + pmatch[0].rm_so, key, strlen(key));
    
    //printf("%s\n", regular_expression);
    
    sec_reti = regcomp(&reg, regular_expression, 0);
    
    if(sec_reti)
    {
      new_buf = apr_palloc(f->r->pool, buf_len + 1);
      memcpy(new_buf, buf, buf_len);
      new_buf[buf_len] = 0;
      return new_buf;
    }
    
    p = buf;
    
    if (!sec_reti)
    {
        puts("successfully match!\n");

        while(!regexec(&reg, p, 1, pmatch, 0)) {
	  i++;
	  p += pmatch[0].rm_eo;
	  if (!p) break;
	}
	Number_eo = apr_palloc(f->r->pool, i * sizeof(int));
	Nonce_Ending_Location = apr_palloc(f->r->pool, i * sizeof(int));

	i = 0;
	p = buf;
        while(!regexec(&reg, p, 1, pmatch, 0))
        {
            
            //Number_so[i] = pmatch[0].rm_so; //Starting location of "nonce" relative to char *p
            Number_eo[i] = pmatch[0].rm_eo; //Ending location of nonce = "key"
            i++;
            p += pmatch[0].rm_eo;
            if (!p)
                break;
        }
        
        for (j = 0; j < i; ++j)
        {
            if (j == 0)
            {
                Nonce_Ending_Location[j] = Number_eo[j];
            }
            else{
                
                //Nonce_Ending_Location[j] = Nonce_Ending_Location[j-1] + Number_eo[j] + 1;
                Nonce_Ending_Location[j] = Nonce_Ending_Location[j-1] + Number_eo[j];
            }
            
        }
        
        new_buf = apr_palloc(f->r->pool, buf_len + i*30 + 1); //assume the length of each nonce is at most 30
        memset(new_buf, 0, buf_len + i*30 + 1);
        
        q = buf;
        w = new_buf;
        //printf("%i\n", i);
        for (j = 0; j < i; ++j)
        {
            if (j == 0)
            {
                strncpy(w, q, Nonce_Ending_Location[j] - strlen(key));
                
                
                strncpy(w + Nonce_Ending_Location[j] - strlen(key), nonce, strlen(nonce));
                
                w = w + Nonce_Ending_Location[j] - strlen(key) + strlen(nonce) ;
                
                
                q = q + Nonce_Ending_Location[j];
                
                
            }
            else{
                //strncpy(w, q, Nonce_Ending_Location[j] - strlen(key) - Nonce_Ending_Location[j-1]-1);
                strncpy(w, q, Nonce_Ending_Location[j] - strlen(key) - Nonce_Ending_Location[j-1]);
                //        strncpy(w + Nonce_Ending_Location[j]- Nonce_Ending_Location[j-1] - strlen(key) -1, nonce, strlen(nonce));
                strncpy(w + Nonce_Ending_Location[j]- Nonce_Ending_Location[j-1] - strlen(key), nonce, strlen(nonce));
                
                
                w = w + Nonce_Ending_Location[j]- Nonce_Ending_Location[j-1] - strlen(key) + strlen(nonce);// - 1;
                q = q + Nonce_Ending_Location[j]- Nonce_Ending_Location[j-1];// -1;
            }
        }
        
        
        //memcpy(w, q, buf_len - Nonce_Ending_Location[i]);
        if(i > 0)
            memcpy(w, q, buf_len - Nonce_Ending_Location[i-1]);
        else
            memcpy(w, q, buf_len);
        //printf("%s\n", new_buf);
    }
    
    regfree(&reg);
    regfree(&reg_key);
    return new_buf;
}


char *get_nonce(ap_filter_t* f) {
  //char *tmp = "ReplaceWithRandom";
  char *nonce = apr_palloc(f->r->pool, MAX_NONCE_LEN + 1);
  //memcpy(nonce, tmp, strlen(tmp));
  char *Alphabet = 
    "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
  
  int i, s;
  for(i=0; i<MAX_NONCE_LEN; ++i) {
      s = rand()%62;
      nonce[i] = Alphabet[s];
   }
  nonce[i] = 0;
  return nonce;
}
