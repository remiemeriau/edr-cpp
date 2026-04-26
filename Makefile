TARGET = antivirus
CXX = g++
CXXFLAGS = -Wall -Wextra -g

# fichiers source et objets correspondants (.cpp → .o)
SRCS = src/main.cpp src/yara.cpp
OBJS = $(SRCS:.cpp=.o)

# règle lancée avec "make"
all: $(TARGET)

# link : crée l'exécutable à partir des fichiers objets
$(TARGET): $(OBJS)
    $(CXX) $(CXXFLAGS) -o $@ $^   # $@ = cible, $^ = tous les .o

# supprime les fichiers générés
clean:
    rm -f $(OBJS) $(TARGET)

.PHONY: all clean