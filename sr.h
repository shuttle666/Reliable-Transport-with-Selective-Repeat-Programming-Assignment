/* Structure to track packet status at sender */
struct packet_status
{
  struct pkt packet;
  int sent;  /* 1 if sent, 0 otherwise */
  int acked; /* 1 if ACKed, 0 otherwise */
};

/* Structure to buffer packets at receiver */
struct buffer
{
  struct pkt packet;
  int valid; /* 1 if valid, 0 otherwise */
};

extern void A_init(void);
extern void B_init(void);
extern void A_input(struct pkt);
extern void B_input(struct pkt);
extern void A_output(struct msg);
extern void A_timerinterrupt(void);

#define BIDIRECTIONAL 0
extern void B_output(struct msg);
extern void B_timerinterrupt(void);
