CC = gcc
CFLAGS = -Wall -Wextra -fPIC -I./include
TARGET = libmysyslog.so

all: $(TARGET)

$(TARGET): libmysyslog.o
	$(CC) -shared -o $(TARGET) libmysyslog.o

libmysyslog.o: libmysyslog.c
	$(CC) $(CFLAGS) -c libmysyslog.c

clean:
	rm -f $(TARGET) *.o

deb: clean all
	# Create directory for .deb output
	mkdir -p ../deb
	
	# Create temporary directory structure
	mkdir -p deb_pkg/usr/bin
	mkdir -p deb_pkg/DEBIAN
	
	# Copy the executable to usr/bin
	install -m 755 $(TARGET) deb_pkg/usr/bin/
	
	# Create control file
	echo "Package: myrpc-client" > deb_pkg/DEBIAN/control
	echo "Version: 1.0-1" >> deb_pkg/DEBIAN/control
	echo "Section: net" >> deb_pkg/DEBIAN/control
	echo "Priority: optional" >> deb_pkg/DEBIAN/control
	echo "Architecture: amd64" >> deb_pkg/DEBIAN/control
	echo "Maintainer: Your Name <you@example.com>" >> deb_pkg/DEBIAN/control
	echo "Description: myRPC Client Application" >> deb_pkg/DEBIAN/control
	
	# Build the package
	fakeroot dpkg-deb --build deb_pkg ../deb/libmysyslog_1.0-1_amd64.deb
	
	# Clean up temporary files
	rm -rf deb_pkg

.PHONY: all clean deb
