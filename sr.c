#include <stdlib.h>
#include <stdio.h>
#include "emulator.h"
#include "sr.h"

#define RTT 16.0
#define WINDOWSIZE 6
#define MAX_SEQ 16 /* SR needs larger sequence space (at least 2*WINDOWSIZE) */
#define NOTINUSE (-1)

/* Sender (A) variables */
static struct pkt buffer[WINDOWSIZE]; /* Buffer for storing packets awaiting ACK */
static int windowfirst; /* Index of the first unacked packet in the buffer */
static int windowcount; /* Number of packets currently awaiting an ACK */
static int A_nextseqnum; /* Next sequence number to be used by the sender */

/* Receiver (B) variables */
static struct pkt recv_buffer[WINDOWSIZE]; /* Buffer for storing received packets at B */
static int expectedseqnum; /* Sequence number of the next expected in-order packet */

/* Compute the checksum of a packet for integrity verification */
int ComputeChecksum(struct pkt packet)
{
  int checksum = 0;
  int i;

  checksum = packet.seqnum;
  checksum += packet.acknum;
  for (i = 0; i < 20; i++)
    checksum += (int)(packet.payload[i]);

  return checksum;
}

/* Check if a packet is corrupted by comparing checksums */
int IsCorrupted(struct pkt packet)
{
  if (packet.checksum == ComputeChecksum(packet))
    return 0; /* false */
  else
    return 1; /* true */
}

/********* Sender (A) functions ************/

/* Called from layer 5: Send a new message to the network */
void A_output(struct msg message)
{
  struct pkt sendpkt;
  int i;

  if (windowcount < WINDOWSIZE)
  {
    if (TRACE > 1)
      printf("----A: New message arrives, send window is not full, send new messge to layer3!\n");

    /* Create a new packet with the given message */
    sendpkt.seqnum = A_nextseqnum;
    sendpkt.acknum = NOTINUSE;
    for (i = 0; i < 20; i++)
      sendpkt.payload[i] = message.data[i];
    sendpkt.checksum = ComputeChecksum(sendpkt);

    /* Store the packet in the buffer at the current position */
    int index = windowcount;
    buffer[index] = sendpkt;
    windowcount++;

    if (TRACE > 0)
      printf("Sending packet %d to layer 3\n", sendpkt.seqnum);
    tolayer3(A, sendpkt);

    /* Start the timer if this is the first packet in the window */
    if (windowcount == 1)
      starttimer(A, RTT);

    A_nextseqnum = (A_nextseqnum + 1) % MAX_SEQ;
  }
  else
  {
    if (TRACE > 0)
      printf("----A: New message arrives, send window is full\n");
    window_full++;
  }
}

/* Called from layer 3: Process an incoming ACK packet */
void A_input(struct pkt packet)
{
  int i;

  if (!IsCorrupted(packet))
  {
    if (TRACE > 0)
      printf("----A: uncorrupted ACK %d is received\n", packet.acknum);
    total_ACKs_received++;

    if (windowcount != 0)
    {
      int acked_idx = -1;
      for (i = 0; i < windowcount; i++)
      {
        if (buffer[i].seqnum == packet.acknum)
        {
          acked_idx = i;
          break;
        }
      }

      if (acked_idx != -1)
      {
        if (TRACE > 0)
          printf("----A: ACK %d is not a duplicate\n", packet.acknum);
        new_ACKs++;

        windowcount--;

        /* Temporarily keep old window sliding logic */
        stoptimer(A);
        if (windowcount > 0)
        {
          for (i = 0; i < windowcount; i++)
          {
            if (buffer[i].seqnum >= windowfirst)
            {
              starttimer(A, RTT);
              break;
            }
          }
        }
      }
      else
      {
        if (TRACE > 0)
          printf("----A: duplicate ACK received, do nothing!\n");
      }
    }
  }
  else
  {
    if (TRACE > 0)
      printf("----A: corrupted ACK is received, do nothing!\n");
  }
}

/* Called when the timer expires: Resend unacknowledged packets */
void A_timerinterrupt(void)
{
  int i;
  int timer_started = 0;

  if (TRACE > 0)
    printf("----A: time out, resend unacked packets!\n");

  for (i = 0; i < windowcount; i++)
  {
    if (buffer[i].seqnum >= windowfirst)
    {
      if (TRACE > 0)
        printf("---A: resending packet %d\n", buffer[i].seqnum);

      tolayer3(A, buffer[i]);
      packets_resent++;
      if (!timer_started)
      {
        starttimer(A, RTT);
        timer_started = 1;
      }
    }
  }
}

/* Initialize sender's state variables */
void A_init(void)
{
  A_nextseqnum = 0;
  windowfirst = 0;
  windowcount = 0;
}

/********* Receiver (B) functions ************/

/* Called from layer 3: Process an incoming packet at B */
void B_input(struct pkt packet)
{
  struct pkt sendpkt;
  int i;

  if ((!IsCorrupted(packet)) && (packet.seqnum == expectedseqnum))
  {
    if (TRACE > 0)
      printf("----B: packet %d is correctly received, send ACK!\n", packet.seqnum);
    packets_received++;

    tolayer5(B, packet.payload);

    sendpkt.acknum = expectedseqnum;

    expectedseqnum = (expectedseqnum + 1) % MAX_SEQ;
  }
  else
  {
    if (TRACE > 0)
      printf("----B: packet corrupted or not expected sequence number, resend ACK!\n");
    if (expectedseqnum == 0)
      sendpkt.acknum = MAX_SEQ - 1;
    else
      sendpkt.acknum = expectedseqnum - 1;
  }

  sendpkt.seqnum = NOTINUSE;

  for (i = 0; i < 20; i++)
    sendpkt.payload[i] = '0';

  sendpkt.checksum = ComputeChecksum(sendpkt);

  tolayer3(B, sendpkt);
}

/* Initialize receiver's state variables */
void B_init(void)
{
  expectedseqnum = 0;
}

void B_output(struct msg message)
{
}

void B_timerinterrupt(void)
{
}