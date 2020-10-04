#include "http_messages.hh"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <iostream>
#include <string>
#include <vector>
#include <unistd.h>
#include <sys/stat.h>
#include <cstdio>
#include <cstdlib>
#include <stdio.h>
#include <unistd.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <dlfcn.h>
std::vector<std::pair<std::string,void *>> module;
// You could implement your logic for handling /cgi-bin requests here
typedef void (*function)(int ssock, char * query_string);
HttpResponse handle_cgi_bin(const HttpRequest& request) {
  HttpResponse response;
  char *requesturi = (char *)request.request_uri.c_str();
  response.http_version = request.http_version;
  std::string query = request.query;
  //get the path before "?"
  std::string path = strtok(requesturi,"?");
  if(request.request_uri.find(".so") != std::string::npos) {
    std::cout << "first\n";
    //if there is .so in the requesturi
    void* directory;
    path = "http-root-dir" + path;
    int contains = 0;
    //check if it is in module
    for(int i = 0; i < module.size();i++) {
      if(module[i].first.find(path) != std::string::npos) {
        contains = 1;
        directory = module[i].second;
      }
    }
    //if it is not in module
    if(contains == 0) {
      directory = dlopen(path.c_str(), RTLD_LAZY);
		  if(directory == NULL){
			  perror("dlopen");
			  exit(1);
		  }
      std::pair<std::string,void*> doc;
      doc.first = path.c_str();;
      doc.second = directory;
      module.push_back(doc);
    }
    function df;
    df = (function)(dlsym(directory, "httprun"));
    if(df == NULL){
		  perror( "dlsym: httprun not found:");
		  exit(1);
	  }
    int fdpipe[2];
    pipe(fdpipe);
    int pid = fork();
    if(pid == 0) {
      std::cout << "hello\n";
      close(fdpipe[0]);
      dup2(fdpipe[1],1);
      df(1, (char *)query.c_str());
		  exit(0);
    }
    waitpid(pid, NULL, 0);
    close(fdpipe[1]);
		char message[9999];
	  read(fdpipe[0], message, sizeof(message));
    response.message_body = message;
    response.status_code = 200;
    response.reason_phrase = "OK";
    std::pair<std::string,std::string> connection;
    connection.first = "Connection";
    connection.second = "close";
    close(fdpipe[0]);
    memset(message, 0, sizeof(message));

  } else {
    std::cout << "second\n";
      int fdpipe[2];
      pipe(fdpipe);
      int pid = fork();
      if(pid == 0) {
        //assign stdout to fdpipe[1]
        dup2(fdpipe[1], 1);
        close(fdpipe[0]);
        //child process
        if(!query.empty()) {
          setenv("QUERY_STRING", request.query.c_str(), 1);
        }
        setenv("REQUEST_METHOD","GET",1);
        path = "./http-root-dir" + path;
        //std::cout << "path is " << path << "\n";
        int result = execl(path.c_str(),"",(char *)NULL);

        if(result < 0) {
          std::cout << "error!";
          exit(0);
        }
        }
      waitpid(pid,NULL,0);
      close(fdpipe[1]);
      //parent process
      char content[9999];;
      read(fdpipe[0], content, sizeof(content));
      response.message_body = content;
      close(fdpipe[0]);
      response.status_code = 200;
      response.reason_phrase = "OK";
      memset(content, 0, sizeof(content));
  }

  // TODO: Task 2.2
  return response;
}
