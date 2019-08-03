#include "send_arp.h"


void show_usage(char **argv);

using std::printf;
using xvzd::SendArp;

int main(int argc, char **argv) {
  if (argc != 4) {
    show_usage(argv);
    return EXIT_FAILURE;
  }
  char *interface = argv[1];
  char *sender_ip = argv[2];
  char *target_ip = argv[3];

  SendArp s(interface, sender_ip, target_ip);
  s.print();

  return EXIT_SUCCESS;
}


void show_usage(char **argv) {
  printf("usage: %s <interface> <sender_ip> <target_ip>\n", argv[0]);
}

