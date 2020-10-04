/**
 * This file contains the primary logic for your server. It is responsible for
 * handling socket communication - parsing HTTP requests and sending HTTP responses
 * to the client. 
 */

#include <functional>
#include <iostream>
#include <string.h>
#include <stdio.h>
#include <sstream>
#include <vector>
#include <tuple>
#include <pthread.h>
#include <limits.h>
#include <sys/wait.h>
#include <unistd.h>
#include <thread>
#include <iomanip>
#include <ctime>
#include <chrono>
#include "server.hh"
#include "http_messages.hh"
#include "errors.hh"
#include "misc.hh"
#include "routes.hh"
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
Server::Server(SocketAcceptor const& acceptor) : _acceptor(acceptor) { }
std::chrono::system_clock::time_point startpoint;
std::vector<std::string> iplist;
std::vector<std::string> routelist;
std::vector<std::string> respcodelist;
pthread_mutex_t mutex;
int numrequest = 0;
std::vector<std::pair<std::chrono::duration<double>,std::string>> timelist;
extern "C" void child(int sig) {
	//if there are zombie processes
	int currentpid;
	while((currentpid = waitpid(-1,NULL,WNOHANG)) > 0) {
	}
}

struct ThreadParams {
  const Server * server;
  Socket_t sock;
};

void dispatchThread(ThreadParams * params) {
  params->server->handle(params->sock);
  delete params;
}

void Server::run_linear() const {
  //kill any zombie processes
  struct sigaction sigchild;
	sigchild.sa_handler = child;
	sigemptyset(&sigchild.sa_mask);
	sigchild.sa_flags = SA_RESTART;
	int error = sigaction(SIGCHLD, &sigchild , NULL);
	if( error ) {
		perror( "sigaction");
	 	exit(-1);
	}
  while (1) {
    Socket_t sock = _acceptor.accept_connection();
    handle(sock);
  }
}

void Server::run_fork() const {
  // TODO: Task 1.4
  //kill zombie processes
  struct sigaction sigchild;
	sigchild.sa_handler = child;
	sigemptyset(&sigchild.sa_mask);
	sigchild.sa_flags = SA_RESTART;
	int error = sigaction(SIGCHLD, &sigchild , NULL);
	if( error ) {
		perror( "sigaction");
	 	exit(-1);
	}
  //let child process to handle the error
  while (1) {
    Socket_t sock = _acceptor.accept_connection();
    int pid = fork();
    if(pid == 0) {
      handle(sock);
      exit(0);
    }
    //waitpid(pid,NULL,0);
  //close(sock);
  }
  
}

void Server::run_thread() const {
  // TODO: Task 1.4
  //kill any zombie processes
  struct sigaction sigchild;
	sigchild.sa_handler = child;
	sigemptyset(&sigchild.sa_mask);
	sigchild.sa_flags = SA_RESTART;
	int error = sigaction(SIGCHLD, &sigchild , NULL);
	if( error ) {
		perror( "sigaction");
	 	exit(-1);
	}
  //let process handle the process
  while (1) {
    Socket_t sock = _acceptor.accept_connection();
    pthread_attr_t attr;
    ThreadParams * threadparams = new ThreadParams;
    threadparams->server = this;
    threadparams->sock = std::move(sock);
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr,PTHREAD_CREATE_DETACHED);
    pthread_t thread;
    pthread_create(&thread,&attr,(void* (*)(void*))dispatchThread,(void *)threadparams);
  }
}

void Server::run_thread_pool(const int num_threads) const {
  // TODO: Task 1.4
  //kill any zombie processes
  struct sigaction sigchild;
	sigchild.sa_handler = child;
	sigemptyset(&sigchild.sa_mask);
	sigchild.sa_flags = SA_RESTART;
	int error = sigaction(SIGCHLD, &sigchild , NULL);
	if( error ) {
		perror( "sigaction");
	 	exit(-1);
	}
  while(1){
	  std::thread threadlist[num_threads];
	  for(int i=0; i<num_threads; i++){
		  threadlist[i]  = std::thread(&Server::run_linear, this);
	  }
	  for(int i=0;i<num_threads; i++){
		  threadlist[i].join();
	  }
  }
}

// example route map. you could loop through these routes and find the first route which
// matches the prefix and call the corresponding handler. You are free to implement
// the different routes however you please
/*
std::vector<Route_t> route_map = {
  std::make_pair("/cgi-bin", handle_cgi_bin),
  std::make_pair("/", handle_htdocs),
  std::make_pair("", handle_default)
};
*/

void parse_request(const Socket_t& sock, HttpRequest* const request) {
  std::string requestline = sock->readline();
  pthread_mutex_lock(&mutex);
  if(requestline.empty()) {
    return;
    //printf("first requestline %s\n",requestline.c_str());
  }
  /*while(requestline.compare("ERROR") == 0) {
    std::string requestline = sock->readline();
    //std::cout << "requestline is " << requestline.c_str() << "\n";
  }*/

  char * crequestline = (char *)requestline.c_str();
  crequestline[strlen(crequestline) - 2] = 0;
  char * token = strtok(crequestline," ");
  int count = 0;
  //split the token by space
  while(token != NULL) {
    if(count == 0) {
      request->method = token;
      count++;
    } else if(count == 1) {
      request->request_uri = token;
      count++;
    } else if (count == 2) {
      //token = strtok(NULL,"\n");
      request->http_version = token;
      count++;
    }
    token = strtok(NULL," ");
  }
  //take request uri separately to check for query
  std::string requesturi = request->request_uri;
  if(requesturi.find("?") != std::string::npos) {
    //find ? in requesturi
    char *query = strtok((char *)requesturi.c_str(),"?");
    query = strtok(NULL, "?");
    request->query = query;
  }
  requestline = sock->readline();
  crequestline = (char *)requestline.c_str();
  while(requestline.compare("\r\n") != 0) {
    std::pair<std::string,std::string> headerpair;
    token = strtok(crequestline," ");
    if(token != NULL) {
    std::string key = token;
    //check for authorization
    if(key.compare("Authorization:") == 0) {
      //jump for string "basic"
      token = strtok(NULL," ");
      token = strtok(NULL," ");
    } else {
      token = strtok(NULL," ");
    }
    if(strlen(token) >= 2) {
      token[strlen(token) - 2] = 0;
    }
    std::string value = token;
    headerpair.first = key;
    headerpair.second = value;
    request->headers.insert(headerpair);
    requestline = sock->readline();
    crequestline = (char *)requestline.c_str();
    }
    
  }
  
}
void Server::handle(const Socket_t& sock) const {
  //pthread_mutex_lock(&mutex);
  auto handlestart =std::chrono::steady_clock::now();
  HttpRequest request;
  // TODO: implement parsing HTTP requests
  // recommendation:
  // void parse_request(const Socket_t& sock, HttpRequest* const request);
  parse_request(sock,&request);
  if(request.method.empty()) {
    pthread_mutex_unlock(&mutex);
    return;
  }
  request.print();

  HttpResponse resp;
  // TODO: Make a response for the HTTP request
  //check if it is equal to /hello
  std::string method = request.method;
  std::string request_url = request.request_uri;
  std::string http_version = request.http_version;
  //hu611:123456
  std::string password = "aHU2MTE6MTIzNDU2";
  //variable to check if the authorization was found
  int find = 0;
  //password that gets input by user
  std::string inputpwd;
  for (auto kvp=request.headers.begin(); kvp != request.headers.end(); kvp++) {
    if(kvp->first.compare("Authorization:") == 0) {
      //find authorization
      find = 1;
      inputpwd = kvp->second;
    }
  }
  //printf("input password is %s\n",inputpwd.c_str());
  //if the user does not type authorization
  if(find == 0) {
    resp.http_version = request.http_version;
    resp.status_code = 401;
	  resp.reason_phrase = "Unauthorized";
	  std::pair<std::string,std::string> unauth;
    unauth.first = "WWW-Authenticate";
    unauth.second = "Basic realm=\"myhttpd-cs252\"";
    resp.headers.insert(unauth);
  } else {
    //if find the authorization
    if(inputpwd != password) {
      //if the password does not match
      resp.http_version = request.http_version;
      resp.status_code = 401;
	    resp.reason_phrase = "Unauthorized";
	    std::pair<std::string,std::string> unauth;
      unauth.first = "WWW-Authenticate";
      unauth.second = "Basic realm=\"myhttpd-cs252\"";
      resp.headers.insert(unauth);
    } else {
      //if the password matches
      numrequest++;
       if(method.compare("GET") == 0 && request_url.compare("/hello") == 0 && http_version.compare("HTTP/1.1") == 0) {
        resp.http_version = request.http_version;
        resp.status_code = 200;
        resp.reason_phrase = "OK";
        std::pair<std::string,std::string> connection;
        connection.first = "Connection";
        connection.second = "close";
        resp.headers.insert(connection);
        std::pair<std::string,std::string> type;
        type.first = "Content-Type";
        type.second = "text/text";
        resp.headers.insert(type);
        std::pair<std::string,std::string> length;
        length.first = "Content-Length";
        length.second = "12";
        resp.headers.insert(length);
        resp.message_body = "Hello CS252!\r\n";
       } 
       else if(request_url.find("/logs") != std::string::npos) {
         //if contains /logs, then source ip, ROUTE, response code
         std::stringstream ss;
        for(int i = 0; i < respcodelist.size();i++) {
          if(!iplist.empty()) {
            ss << iplist[i].c_str() << "\t";
          } else {
            ss << "\t";
          }
          if(!routelist.empty()) {
            ss << routelist[i].c_str() << "\t";
          } else {
            ss << "\t";
          }
          if(!respcodelist.empty()) {
            ss << respcodelist[i].c_str() << "\t";
          } else {
            ss << "\t";
          }
          ss << std::endl;
        }
        int fd = open("myhttpd.log",O_WRONLY|O_CREAT|O_APPEND, 0700);
        std::string buffer(ss.str());
        write(fd,buffer.c_str(),buffer.size());
        resp.status_code = 200;
        resp.reason_phrase = "OK";
        resp.http_version = request.http_version;
        std::pair<std::string,std::string> connection;
        connection.first = "Connection";
        connection.second = "close";
        resp.headers.insert(connection);
        resp.message_body = ss.str();
        close(fd);
       } 
       else if(request_url.find("/stats") != std::string::npos) {
         //show stat page
        std::chrono::duration<double,std::milli> elapsed_time = std::chrono::system_clock::now() - startpoint;

        //stats process data
        std::chrono::duration<double,std::milli> elapsed_seconds = std::chrono::steady_clock::now() - handlestart;
        std::pair<std::chrono::duration<double>,std::string> timepair;
        timepair.first = elapsed_seconds;
        timepair.second = request.request_uri;
        timelist.push_back(timepair);

        //start printing process
        std::stringstream ss;
        ss << "Name: Weiyan Hu" << "\n" << std::endl;
        ss << "The uptime of the server: " << elapsed_time.count() << "ms\n" << std::endl;
        ss << "Number of request is " << numrequest << "\n" << std::endl;
       
        double maxservicetime = 0;
        std::string maxservicetimeurl;
        double minservicetime = 99999;
        std::string minservicetimeurl;
        for(int i = 0; i < timelist.size();i++) {
          std::stringstream sa;
          sa << timelist[i].first.count() << std::endl;
          double x = 0;
          sa >> x;
          if(x > maxservicetime) {
            maxservicetime = x;
            maxservicetimeurl = timelist[i].second;
          }
          if(x < minservicetime) {
           minservicetime = x;
           minservicetimeurl = timelist[i].second;
          }
        }
        if(minservicetime == 99999) {
          //if there is no process
          minservicetime = 0;
        }
        ss << "The maximum service time of the server: " << maxservicetime << "ms\n" << std::endl;
        ss << "The URL for the maximum service time of the server: " << maxservicetimeurl << "\n" << std::endl;
        ss << "The minimum service time of the server: " << minservicetime << "ms\n" << std::endl;
        ss << "The URL for the minimum service time of the server: " << minservicetimeurl << "\n" << std::endl;
        resp.status_code = 200;
        resp.reason_phrase = "OK";
        resp.http_version = request.http_version;
        std::pair<std::string,std::string> connection;
        connection.first = "Connection";
        connection.second = "close";
        resp.headers.insert(connection);
        resp.message_body = ss.str();
       } 
       else if(request_url.find("/cgi-bin") != std::string::npos){
         std::cout << "find cgi-bins\n";
        resp = handle_cgi_bin(request);
       } else {
         std::cout << "find htdocs\n";
        //resp.message_body = "Hello CS252!\r\n";
        resp = handle_htdocs(request);
       }
    }
  }
  routelist.push_back(std::string(request.request_uri));
  respcodelist.push_back(std::to_string(resp.status_code));
  //resp.http_version = "HTTP/1.1";
  std::cout << resp.to_string() << std::endl;
  sock->write(resp.to_string());
  auto handleend =std::chrono::steady_clock::now();
  std::chrono::duration<double> elapsed_seconds = handleend - handlestart;
  std::pair<std::chrono::duration<double,std::milli>,std::string> timepair;
  timepair.first = elapsed_seconds;
  timepair.second = request.request_uri;
  timelist.push_back(timepair);
  pthread_mutex_unlock(&mutex);
}
