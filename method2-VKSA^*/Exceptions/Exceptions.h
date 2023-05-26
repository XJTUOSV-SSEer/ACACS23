// (C) 2019 University of NKU. Free for used
// Author: stoneboat@mail.nankai.edu.cn

/*
* Exceptions.h
*
*/

#ifndef _Exceptions
#define _Exceptions

#include <exception>
#include <string>
#include <sstream>
#include <stdexcept>

class file_error:  public std::exception
{
	std::string filename, ans;
  	public:
	 	file_error(std::string m="") : filename(m)
	    {
	      ans="File Error : ";
	      ans+=filename;
	    }
	 	~file_error()throw() { }
	 	virtual const char* what() const throw()
	    {
	      return ans.c_str();
	    }
};

class Processor_Error: public std::exception
{ std::string msg;
  public:
  Processor_Error(std::string m)
    {
      msg = "Processor-Error : " + m;
    }
  ~Processor_Error()throw() { }
  virtual const char* what() const throw()
    {
      return msg.c_str();
    }
};

class invalid_length: public std::runtime_error
{
public:
  invalid_length(std::string msg = "") : std::runtime_error("Invalid length: " + msg) {}
};

class bad_value: public std::exception
{ virtual const char* what() const throw()
    { return "Some value is wrong somewhere"; }
};


class token_map_Error:  public std::exception
{ 
  std::string filename, ans;
    public:
    token_map_Error(std::string m="") : filename(m)
      {
        ans="can not found the token map info for wid : ";
        ans+=filename;
      }
    ~token_map_Error()throw() { }
    virtual const char* what() const throw()
      {
        return ans.c_str();
      }
};

class IO_Error: public std::exception
{ std::string msg, ans;
  public:
  IO_Error(std::string m) : msg(m)
    { ans="IO-Error : ";
      ans+=msg;
    }
  ~IO_Error()throw() { }
  virtual const char* what() const throw()
    {
      return ans.c_str(); 
    }
};

class db_Error: public std::exception
{ std::string msg, ans;
  public:
  db_Error(std::string m) : msg(m)
    { ans="database operation error : ";
      ans+=msg;
    }
  ~db_Error()throw() { }
  virtual const char* what() const throw()
    {
      return ans.c_str(); 
    }
};








#endif