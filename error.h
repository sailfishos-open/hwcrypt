#ifndef _ERROR_INCLUDED_

#include <iostream>

class Error {
public:
  explicit Error(int code = 1) : code_(code) {}

  ~Error() { std::cerr << std::endl; }

  template <typename T> Error &operator<<(const T &value) {
    std::cerr << value;
    return *this;
  }

  operator int() const { return code_; }

private:
  int code_;
};

#endif
