#include "fscrypt.h"
#include "string.h"
#include <stdio.h>

void *fs_encrypt(void *plaintext, int bufsize, char *keystr, int *resultlen){
    BF_KEY key;
    BF_set_key(&key,strlen(keystr),(const unsigned char *) keystr);
    char* buffer;
    
    char* pt = static_cast<char*> (plaintext);

    int low = 0;
    int high = BLOCKSIZE;
    
    char IV[BLOCKSIZE]={0,0,0,0,0,0,0,0};
    unsigned char array[BLOCKSIZE];
    unsigned char out[BLOCKSIZE];          
    if(bufsize%BLOCKSIZE==0){
        buffer = new char[bufsize+8];
        *resultlen = bufsize;
        int multiple = (bufsize)/BLOCKSIZE;

        for(int j=low;j<high;j++){
                array[j-low]=pt[j];
 
            }
        for(int i=0;i<BLOCKSIZE;i++){
                array[i]=IV[i]^ array[i];
            } 
        BF_ecb_encrypt((const unsigned char *) array,out,&key,1);
        for(int i=0;i<BLOCKSIZE;i++){
               buffer[low+i]=out[i];
            } 
            low+=BLOCKSIZE;
            high+=BLOCKSIZE;
        for(int i =0;i<multiple;i++){     
            for(int j=low;j<high;j++){
                array[j-low]=pt[j];
            }
            for(int i=0;i<BLOCKSIZE;i++){
                array[i]=out[i]^ array[i];
            } 
            BF_ecb_encrypt((const unsigned char *) array,out,&key,1);
            for(int i=0;i<BLOCKSIZE;i++){
                buffer[low+i]=out[i];
                } 
            low+=BLOCKSIZE;
            high+=BLOCKSIZE;
        }
        for(int j=low;j<high;j++){
                array[j-low]=BLOCKSIZE;
            }
        for(int i=0;i<BLOCKSIZE;i++){
            array[i]=out[i]^ array[i];
        } 
        BF_ecb_encrypt((const unsigned char *) array,out,&key,1);
        for(int i=0;i<BLOCKSIZE;i++){
            buffer[low+i]=out[i];
        } 
    }   
    else if(bufsize<BLOCKSIZE){
        buffer = new char[BLOCKSIZE];
        *resultlen = bufsize;
        int dif = BLOCKSIZE-bufsize;
        for(int i=0;i<BLOCKSIZE;i++){
            if(i>=bufsize){
                array[i]=dif;
            }
            else{
                array[i]=pt[i];
            }
        }
        for(int i=0;i<BLOCKSIZE;i++){
            array[i]=IV[i]^ array[i];
        } 
        BF_ecb_encrypt((const unsigned char *) array,out,&key,1);
        for(int i=0;i<BLOCKSIZE;i++){
            buffer[low+i]=out[i];
        } 
    }
    else{

        buffer = new char[bufsize+(bufsize%BLOCKSIZE)];
        *resultlen = bufsize;
        int multiple = bufsize/BLOCKSIZE;

        for(int j=low;j<high;j++){
                array[j-low]=pt[j];
 
            }
        for(int i=0;i<BLOCKSIZE;i++){
                array[i]=IV[i]^ array[i];
            } 
        BF_ecb_encrypt((const unsigned char *) array,out,&key,1);
        for(int i=0;i<BLOCKSIZE;i++){
               buffer[low+i]=out[i];
            } 
            low+=BLOCKSIZE;
            high+=BLOCKSIZE;
        for(int i =0;i<multiple;i++){     
            for(int j=low;j<high;j++){
                array[j-low]=pt[j];
            }
            for(int i=0;i<BLOCKSIZE;i++){
                array[i]=out[i]^ array[i];
            } 
            BF_ecb_encrypt((const unsigned char *) array,out,&key,1);
            for(int i=0;i<BLOCKSIZE;i++){
                buffer[low+i]=out[i];
                } 
            low+=BLOCKSIZE;
            high+=BLOCKSIZE;
        }
        int dif = BLOCKSIZE-(bufsize%BLOCKSIZE);
        for(int j=low;j<high;j++){
            if(j>=bufsize){
                array[j-low]=dif;
            }
                array[j-low]=pt[j];
            }
        for(int i=0;i<BLOCKSIZE;i++){
            array[i]=out[i]^ array[i];
        } 
        BF_ecb_encrypt((const unsigned char *) array,out,&key,1);
        for(int i=0;i<BLOCKSIZE;i++){
            buffer[low+i]=out[i];
        } 
    }  

    return (void *) buffer;
}

void *fs_decrypt(void *ciphertext, int bufsize, char *keystr, int *resultlen){
              
  
    BF_KEY key;
    BF_set_key(&key,strlen(keystr),(const unsigned char *) keystr);
    char* buffer;
    char b[bufsize+8];
    char* ct = static_cast<char*> (ciphertext);
    int low = 0;
    int high = BLOCKSIZE;
    
    char IV[BLOCKSIZE]={0,0,0,0,0,0,0,0};
    unsigned char array[BLOCKSIZE];
    unsigned char out[BLOCKSIZE];    
    unsigned char prev[BLOCKSIZE];   
    
 
    if(bufsize%BLOCKSIZE==0){    
        buffer = new char[bufsize+8];
        *resultlen = bufsize; 
        int multiple = ((bufsize)/BLOCKSIZE)+1;
        for(int j=low;j<high;j++){
                array[j-low]=ct[j];
                prev[j-low]=ct[j];
 
            }   
        BF_ecb_encrypt((const unsigned char *) array,out,&key,0);
        for(int i=0;i<BLOCKSIZE;i++){
            array[i]=IV[i]^ out[i];
        } 
        for(int i=0;i<BLOCKSIZE;i++){
               buffer[low+i]=array[i];
            } 
            low+=BLOCKSIZE;
            high+=BLOCKSIZE;
        for(int i =0;i<multiple;i++){       
            for(int j=low;j<high;j++){
                array[j-low]=ct[j];
            }
            BF_ecb_encrypt((const unsigned char *) array,out,&key,0);
            for(int i=0;i<BLOCKSIZE;i++){
                array[i]=out[i]^ prev[i];
            } 
            for(int j=low;j<high;j++){
                prev[j-low]=ct[j];
            }
            for(int i=0;i<BLOCKSIZE;i++){
                buffer[low+i]=array[i];
                } 
            low+=BLOCKSIZE;
            high+=BLOCKSIZE;
        }
        
        for(int j=low;j<high;j++){
            array[j-low]=ct[j];
        }
        BF_ecb_encrypt((const unsigned char *) array,out,&key,0);
        for(int i=0;i<BLOCKSIZE;i++){
            array[i]=prev[i]^ out[i];
        } 
        for(int i=0;i<BLOCKSIZE;i++){
            buffer[low+i]=array[i];
        } 
        
    }   
    else if(bufsize<BLOCKSIZE){
        buffer = new char[bufsize];
        *resultlen = bufsize;
        int dif = BLOCKSIZE-bufsize;
        for(int i=0;i<BLOCKSIZE;i++){
                array[i]=ct[i];
            
        }
        BF_ecb_encrypt((const unsigned char *) array,out,&key,0);
        for(int i=0;i<BLOCKSIZE;i++){
            array[i]=IV[i]^ array[i];
        } 
        for(int i=0;i<BLOCKSIZE;i++){
             array[i]=IV[i]^ out[i];
        } 
        for(int i=0;i<BLOCKSIZE;i++){
               buffer[low+i]=array[i];
        } 
    }
    else{
        buffer = new char[bufsize+(bufsize%BLOCKSIZE)];
        *resultlen = bufsize;
        int multiple = (bufsize+(bufsize%BLOCKSIZE))/BLOCKSIZE;

        for(int j=low;j<high;j++){
                array[j-low]=ct[j];
                prev[j-low]=ct[j];
            }
        BF_ecb_encrypt((const unsigned char *) array,out,&key,0);
        for(int i=0;i<BLOCKSIZE;i++){
            array[i]=IV[i]^ out[i];
        } 
        for(int i=0;i<BLOCKSIZE;i++){
               buffer[low+i]=array[i];
            } 
            low+=BLOCKSIZE;
            high+=BLOCKSIZE;
        for(int i =0;i<multiple;i++){     
            for(int j=low;j<high;j++){
                array[j-low]=ct[j];
            }
            BF_ecb_encrypt((const unsigned char *) array,out,&key,0);
            for(int i=0;i<BLOCKSIZE;i++){
                array[i]=out[i]^ prev[i];
            } 
            for(int j=low;j<high;j++){
                prev[j-low]=ct[j];
            }
            for(int i=0;i<BLOCKSIZE;i++){
                buffer[low+i]=array[i];
            } 
            low+=BLOCKSIZE;
            high+=BLOCKSIZE;
        }
        for(int j=low;j<high;j++){
            array[j-low]=ct[j];
        }
        BF_ecb_encrypt((const unsigned char *) array,out,&key,0);
        for(int i=0;i<BLOCKSIZE;i++){
            array[i]=prev[i]^ out[i];
        } 
        for(int i=0;i<BLOCKSIZE;i++){
            buffer[low+i]=array[i];
        } 
    }  
    return (void *)buffer;
}
