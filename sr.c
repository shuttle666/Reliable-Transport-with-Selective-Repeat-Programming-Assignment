#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include "emulator.h"
#include "sr.h"

#define RTT 16.0
#define WINDOWSIZE 6
#define MAX_SEQ 16 /* SR needs larger sequence space (at least 2*WINDOWSIZE) */
#define NOTINUSE (-1)

static struct packet_status buffer[WINDOWSIZE]; /* Modified to packet_status for SR */
static struct buffer recv_buffer[WINDOWSIZE];   /* Added for receiver buffering */
static int windowfirst, windowlast;
static int windowcount;
static int A_nextseqnum;
static int expectedseqnum;
static int B_nextseqnum;

/* Checksum and corruption functions (unchanged) */
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

bool IsCorrupted(struct pkt packet)
{
  if (packet.checksum == ComputeChecksum(packet))
    return (false);
  else
    return (true);
}

/********* Sender (A) variables and functions ************/

void A_output(struct msg message)
{
  struct pkt sendpkt;
  int i;

  if (windowcount < WINDOWSIZE)
  {
    if (TRACE > 1)
      printf("----A: New message arrives, send window is not full, send new messge to layer3!\n");

    sendpkt.seqnum = A_nextseqnum;
    sendpkt.acknum = NOTINUSE;
    for (i = 0; i < 20; i++)
      sendpkt.payload[i] = message.data[i];
    sendpkt.checksum = ComputeChecksum(sendpkt);

    windowlast = (windowlast + 1) % WINDOWSIZE;
    buffer[windowlast].packet = sendpkt;
    buffer[windowlast].sent = 1;
    buffer[windowlast].acked = 0;
    windowcount++;

    if (TRACE > 0)
      printf("Sending packet %d to layer 3\n", sendpkt.seqnum);
    tolayer3(A, sendpkt);

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

void A_input(struct pkt packet)
{
  int ackcount = 0;
  int i;

  if (!IsCorrupted(packet))
  {
    if (TRACE > 0)
      printf("----A: uncorrupted ACK %d is received\n", packet.acknum);
    total_ACKs_received++;

    if (windowcount != 0)
    {
      int seqfirst = buffer[windowfirst].packet.seqnum; /* Updated to buffer[i].packet */
      int seqlast = buffer[windowlast].packet.seqnum;   /* Updated to buffer[i].packet */
      if (((seqfirst <= seqlast) && (packet.acknum >= seqfirst && packet.acknum <= seqlast)) ||
          ((seqfirst > seqlast) && (packet.acknum >= seqfirst || packet.acknum <= seqlast)))
      {

        if (TRACE > 0)
          printf("----A: ACK %d is not a duplicate\n", packet.acknum);
        new_ACKs++;

        if (packet.acknum >= seqfirst)
          ackcount = packet.acknum + 1 - seqfirst;
        else
          ackcount = MAX_SEQ - seqfirst + packet.acknum;

        windowfirst = (windowfirst + ackcount) % WINDOWSIZE;

        for (i = 0; i < ackcount; i++)
          windowcount--;

        stoptimer(A);
        if (windowcount > 0)
          starttimer(A, RTT);
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

void A_timerinterrupt(void)
{
  int i;

  if (TRACE > 0)
    printf("----A: time out,resend packets!\n");

  for (i = 0; i < windowcount; i++)
  {
    if (TRACE > 0)
      printf("---A: resending packet %d\n", (buffer[(windowfirst + i) % WINDOWSIZE]).packet.seqnum); /* Updated to buffer[i].packet */

    tolayer3(A, buffer[(windowfirst + i) % WINDOWSIZE].packet); /* Updated to buffer[i].packet */
    packets_resent++;
    if (i == 0)
      starttimer(A, RTT);
  }
}

void A_init(void)
{
  A_nextseqnum = 0;
  windowfirst = 0;
  windowlast = -1;
  windowcount = 0;
  for (int i = 0; i < WINDOWSIZE; i++)
  {
    buffer[i].sent = 0;
    buffer[i].acked = 0;
  }
}

/********* Receiver (B) variables and procedures ************/

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

  sendpkt.seqnum = B_nextseqnum;
  B_nextseqnum = (B_nextseqnum + 1) % 2;

  for (i = 0; i < 20; i++)
    sendpkt.payload[i] = '0';

  sendpkt.checksum = ComputeChecksum(sendpkt);

  tolayer3(B, sendpkt);
}

void B_init(void)
{
  expectedseqnum = 0;
  B_nextseqnum = 1;
}

void B_output(struct msg message)
{
}

void B_timerinterrupt(void)
{
}