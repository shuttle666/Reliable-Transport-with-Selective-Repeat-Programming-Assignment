#include <stdlib.h>
#include <stdio.h>
#include "emulator.h"
#include "sr.h"

#define RTT 16.0
#define WINDOWSIZE 6
#define MAX_SEQ 16 /* SR needs larger sequence space (at least 2*WINDOWSIZE) */
#define NOTINUSE (-1)

static struct packet_status buffer[WINDOWSIZE];
static struct buffer recv_buffer[WINDOWSIZE]; 
static int windowfirst, windowlast;
static int windowcount;
static int A_nextseqnum;
static int expectedseqnum;
static int B_nextseqnum;

/* Checksum and corruption functions */
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

int IsCorrupted(struct pkt packet)
{
  if (packet.checksum == ComputeChecksum(packet))
    return 0; /* false */
  else
    return 1; /* true */
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

        buffer[acked_idx].acked = 1;

        while (windowcount > 0 && buffer[windowfirst].acked == 1)
        {
          windowcount--;
          windowfirst = (windowfirst + 1) % WINDOWSIZE;
        }

        stoptimer(A);
        if (windowcount > 0)
        {
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

void A_timerinterrupt(void)
{
  int i;
  int timer_started = 0;

  if (TRACE > 0)
    printf("----A: time out, resend unacked packets!\n");

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
  int i;

  A_nextseqnum = 0;
  windowfirst = 0;
  windowlast = -1;
  windowcount = 0;
  for (i = 0; i < WINDOWSIZE; i++)
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

  if (!IsCorrupted(packet))
  {
    int relative_seqnum = (packet.seqnum - expectedseqnum + MAX_SEQ) % MAX_SEQ;
    if (relative_seqnum < WINDOWSIZE)
    {
      int idx = (expectedseqnum + relative_seqnum) % WINDOWSIZE;

      if (!recv_buffer[idx].valid)
      {
        if (TRACE > 0)
          printf("----B: packet %d is correctly received, send ACK!\n", packet.seqnum); /* 只在首次接收时打印 */
        packets_received++;

        recv_buffer[idx].packet = packet;
        recv_buffer[idx].valid = 1;

        /* 按序交付 */
        while (recv_buffer[expectedseqnum % WINDOWSIZE].valid)
        {
          tolayer5(B, recv_buffer[expectedseqnum % WINDOWSIZE].packet.payload);
          recv_buffer[expectedseqnum % WINDOWSIZE].valid = 0;
          expectedseqnum = (expectedseqnum + 1) % MAX_SEQ;
        }
      }

      /* 发送当前 expectedseqnum 的 ACK */
      sendpkt.acknum = expectedseqnum;
    }
    else
    {
      if (TRACE > 0)
        printf("----B: packet corrupted or not expected sequence number, resend ACK!\n");
      sendpkt.acknum = (expectedseqnum == 0) ? (MAX_SEQ - 1) : (expectedseqnum - 1);
    }
  }
  else
  {
    if (TRACE > 0)
      printf("----B: packet corrupted or not expected sequence number, resend ACK!\n");
    sendpkt.acknum = (expectedseqnum == 0) ? (MAX_SEQ - 1) : (expectedseqnum - 1);
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
  int i;

  expectedseqnum = 0;
  B_nextseqnum = 1;
  for (i = 0; i < WINDOWSIZE; i++)
  {
    recv_buffer[i].valid = 0;
  }
}

void B_output(struct msg message)
{
}

void B_timerinterrupt(void)
{
}