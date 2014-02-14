#! /usr/bin/env python

'''
Utility to reset the user's health to full health. Currently uses fixed
addresses found using gdb.
'''

import argparse
import logging
import psutil

from ptrace.debugger.debugger import PtraceDebugger

logging.basicConfig(level=logging.DEBUG)


def find_hack_pid():
  '''
  Find the hack process, return its PID or -1 if not found.
  '''
  for proc in psutil.process_iter():
    # Only check the last component of path
    if proc.name.split('/')[-1] == 'hack':
      return proc.pid
  else:
    return -1


def main():
  parser = argparse.ArgumentParser(
      description='Utility to reset user\'s health to full.')
  parser.add_argument('pid', nargs='?', type=int,
      help='Specify the PID of the game')

  args = parser.parse_args()

  pid = args.pid
  if not pid:
    pid = find_hack_pid()

  if pid == -1:
    logging.error('Unable to find hack process to attach to.')
    return

  dbg = PtraceDebugger()
  proc = dbg.addProcess(pid, False)

  # Read the value for full health, need just the lower 4 bytes
  full_hp = proc.readWord(0x6425a0) & 0xffffffff

  # Value is (curr hp, ???)
  value = proc.readWord(0x642598)

  curr_hp = value >> 32

  logging.info('Changing health from %d -> %d', curr_hp, full_hp)

  # Calculate the new value to write back
  value = (full_hp << 32) + (value & 0xffffffff)

  # Write the new value
  proc.writeWord(0x642598, value)

  dbg.quit()


if __name__ == '__main__':
  main()
