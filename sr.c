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
      /* Find the packet in the window with the matching seqnum */
      int acked_idx = -1;
      for (i = 0; i < windowcount; i++)
      {
        int idx = (windowfirst + i) % WINDOWSIZE;
        if (buffer[idx].packet.seqnum == packet.acknum)
        {
          acked_idx = idx;
          break;
        }
      }

      if (acked_idx != -1 && buffer[acked_idx].acked == 0)
      {
        if (TRACE > 0)
          printf("----A: ACK %d is not a duplicate\n", packet.acknum);
        new_ACKs++;

        /* Mark the packet as acked */
        buffer[acked_idx].acked = 1;

        /* Slide window if possible (move windowfirst to the first unacked packet) */
        while (windowcount > 0 && buffer[windowfirst].acked == 1)
        {
          windowcount--;
          windowfirst = (windowfirst + 1) % WINDOWSIZE;
        }

        /* Restart timer if there are still unacked packets */
        stoptimer(A);
        if (windowcount > 0)
        {
          /* Find the first unacked packet to set the timer */
          for (i = 0; i < windowcount; i++)
          {
            int idx = (windowfirst + i) % WINDOWSIZE;
            if (buffer[idx].acked == 0)
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
    printf("----A: time out, resend unacked packets!\n");

  /* Only resend packets that are not acked */
  int timer_started = 0;
  for (i = 0; i < windowcount; i++)
  {
    int idx = (windowfirst + i) % WINDOWSIZE;
    if (buffer[idx].sent == 1 && buffer[idx].acked == 0)
    {
      if (TRACE > 0)
        printf("---A: resending packet %d\n", buffer[idx].packet.seqnum);

      tolayer3(A, buffer[idx].packet);
      packets_resent++;
      if (!timer_started)
      {
        starttimer(A, RTT);
        timer_started = 1;
      }
    }
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