/* Copyright (C) 2000 edwards@bitchx.dimension6.com
   This is free software distributed under the terms of the
   GNU Public License.  See the file COPYING for details.

   Modified by drscholl@users.sourceforge.net 2/29/2000.

   $Id$ */

#include <time.h>
#include <stdlib.h>
#include "opennap.h"
#include "debug.h"

typedef struct _timerstruct
{
    struct _timerstruct *next;
    timer_cb_t func;
    void *arg;
    time_t next_time;
    time_t interval;
    int events;
    int refnum;
}
TIMER;

static TIMER *Pending_Timers = NULL;

static void
schedule_timer (TIMER * ntimer)
{
    TIMER **slot;

    if (!ntimer->events)
	return;

    /* we've created it, now put it in order */
    for (slot = &Pending_Timers; *slot; slot = &(*slot)->next)
    {
	if (ntimer->next_time < (*slot)->next_time)
	    break;
    }
    ntimer->next = *slot;
    *slot = ntimer;
}

static int
make_refnum (void)
{
    int count = 0;
    TIMER *tmp;

    for (tmp = Pending_Timers; tmp; tmp = tmp->next, count++)
	;
    return count + 1;
}

void
add_timer (int interval, int events, timer_cb_t func, void *arg)
{
    TIMER *new;

    if (!events)
	return;
    new = CALLOC (1, sizeof (TIMER));
    if (!new)
    {
	OUTOFMEMORY ("add_timer");
	return;
    }
    new->next_time = Current_Time + interval;
    new->interval = interval;
    new->func = func;
    new->arg = arg;
    new->events = events;
    new->refnum = make_refnum ();
    schedule_timer (new);
}

void
exec_timers (time_t now)
{
    TIMER *current;

    while (Pending_Timers && Pending_Timers->next_time <= now)
    {
	current = Pending_Timers;
	Pending_Timers = current->next;
	(*current->func) (current->arg);
	switch (current->events)
	{
	case 0:
	    FREE (current);
	    break;
	default:
	    current->events--;
	case -1:
	    /* reschedule */
	    current->next_time = Current_Time + current->interval;
	    schedule_timer (current);
	    break;
	}
    }
}

/* returns the time offset at which the next pending event is scheduled */
time_t next_timer (void)
{
    if (Pending_Timers)
    {
	if (Pending_Timers->next_time < Current_Time)
	    return 0;		/* now! */
	return (Pending_Timers->next_time - Current_Time);
    }
    return -1;
}

void
free_timers (void)
{
    TIMER *ptr;

    while (Pending_Timers)
    {
	ptr = Pending_Timers;
	Pending_Timers = Pending_Timers->next;
	FREE (ptr);
    }
}
