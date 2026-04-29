TARGET = antivirus
CXX = g++
CXXFLAGS = -Wall -Wextra -g -Iinclude

all: $(TARGET)

$(TARGET): src/main.cpp src/yara.cpp
	$(CXX) $(CXXFLAGS) -o $@ $^

clean:
	rm -f $(TARGET)

.PHONY: all clean
