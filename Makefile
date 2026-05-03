TARGET = edr
CXX = g++
CXXFLAGS = -Wall -Wextra -g -Iinclude
LFLAGS = -lpcap

all: $(TARGET)

$(TARGET): src/main.cpp src/yara.cpp src/dpi.cpp src/ioc.cpp src/logger.cpp
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LFLAGS)

clean:
	rm -f $(TARGET)

.PHONY: all clean
