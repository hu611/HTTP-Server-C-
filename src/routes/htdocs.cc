#include "http_messages.hh"
#include <unistd.h>
#include <string>
#include <string.h>
#include <iostream>
#include <fstream>
#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include "misc.hh"
#include <stdio.h>
#include <stdlib.h>

// You may find implementing this function and using it in server.cc helpful

HttpResponse handle_htdocs(const HttpRequest& request) {
  HttpResponse response;
  response.http_version = request.http_version;
  //give this a relative path
  std::string path = "http-root-dir/htdocs" + request.request_uri;
  std::ifstream file;
  DIR * dir;
  dir = opendir(path.c_str());
  int browse = 0;
  if(dir != NULL) {
    //if it is a directory
    if(path.c_str()[path.size() - 1] == '/') {

      browse = 1;
    } else {
    path = path + "/index.html";
    }
  }
  if(browse == 1) {
    std::stringstream html;
		html << "<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML//EN\">" << std::endl;
		html << "<html>" << std::endl;
		html << "<body>" << std::endl;
		html << "<ul>" << std::endl;
    for(dirent * ent = readdir(dir); NULL != ent; ent = readdir(dir)) {
      std::string link = request.request_uri + ent->d_name;
			link = "<li><a href=\"" + link + "\">";
      link = link + ent->d_name + "</a>";
			html << link << std::endl;
    }
    html << "</ul>" << std::endl;
		html << "</body>" << std::endl;
		html << "</html>" << std::endl;
    std::cout << "html string is " << html.str();
		response.message_body = html.str();
     response.status_code = 200;
    response.reason_phrase = "OK";
    std::pair<std::string,std::string> connection;
    connection.first = "Connection";
    connection.second = "close";
    response.headers.insert(connection);
    std::pair<std::string,std::string> type;
    type.first = "Content-Type";
    std::string str2 = "inode/directory;charset=binary";
    std::string str3 = "inode/x-empty;charset=binary";
    //type.second = "text/text";
    //std::string absolutepath = "/homes/hu611/cs252/lab5-src/http-root-dir/htdocs/index.html";
    if(get_content_type(path).compare(str2) == 0) {
      type.second = "text/html";
    } else {
      type.second = "text/text";
    }
    response.headers.insert(type);
    closedir(dir);
  } else {
  file.open(path);
  if(!file) {
    response.status_code = 404;
		response.reason_phrase = "Not Found!";
		response.message_body = "Cannot open file!";
  } else {
    response.status_code = 200;
    response.reason_phrase = "OK";
    std::pair<std::string,std::string> connection;
    connection.first = "Connection";
    connection.second = "close";
    response.headers.insert(connection);
    std::pair<std::string,std::string> type;
    type.first = "Content-Type";
    //type.second = "text/text";
    //std::string absolutepath = "/homes/hu611/cs252/lab5-src/http-root-dir/htdocs/index.html";
    std::string str3 = "inode/x-empty;charset=binary";
    if(get_content_type(path).compare(str3) != 0) {
      type.second = get_content_type(path);
    } else {
      type.second = "text/html";
    }
    response.headers.insert(type);
    std::stringstream buffer;
    buffer << file.rdbuf();
    //std::string msg = "";
    /*if (file.is_open()) {
    std::string line;
    while (std::getline(file, line)) {
        // using printf() in all tests for consistency
        msg = msg + line.c_str();
        msg = msg + "\n";
    }*/
    response.message_body = buffer.str();
    file.close();
    std::pair<std::string,std::string> length;
    length.first = "Content-Length";
    FILE * f = fopen(path.c_str(), "r");
    fseek(f, 0, SEEK_END);
    int slen = ftell(f);
    
    //int slen = sizeof(file)/sizeof(char);
    //printf("string is %s\n",slen.c_str());
    length.second = std::to_string(slen);
    response.headers.insert(length);
    fclose(f);
    file.close();
  }
  }
  return response;
}
