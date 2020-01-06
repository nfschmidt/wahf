#!/usr/bin/env python3.7

import subprocess
import json
import threading
from queue import Queue


class Program:
    
    def __init__(self, name, command, output_to_stdout=False):
        self._name = name
        self._command = command
        self._registered = []
        self._output_to_stdout = output_to_stdout

        self.in_queue = Queue()

    def start(self):
        self._process = subprocess.Popen(
            self._command,
            shell=True,
            bufsize=0,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE)

        self._run_thread = threading.Thread(
            target=self._run,
            daemon=True)
        self._run_thread.start()

        self._broadcast_output_thread = threading.Thread(
            target=self._broadcast_output,
            daemon=True)
        self._broadcast_output_thread.start()

    def register(self, prog):
        self._registered.append(prog)

    def join(self):
        self.in_queue.join()
        self._run_thread.join()
        self._broadcast_output_thread.join()

    def _run(self):
        while True:
            line = self.in_queue.get()
            if line is None:
                break

            if not line.endswith('\n'):
                line += '\n'

            self._process.stdin.write(line.encode('utf-8'))
            self.in_queue.task_done()

    def _broadcast_output(self):
        for line in iter(self._process.stdout.readline, ''):
            line = line.decode('utf-8').strip()
            for p in self._registered:
                p.in_queue.put(line)

            if self._output_to_stdout:
                print(f'{self._name}|{line}')


class ProgramSet:
    
    def __init__(self, programs_definitions):
        self._programs = self._make_programs(programs_definitions)

    def _make_programs(self, programs_definitions):
        programs = {}

        # create programs with initial inputs
        for name, defn in programs_definitions.items():
            programs[name] = Program(
                name=name,
                command=defn['command'],
                output_to_stdout=defn.get('output_to_stdout', False))

            for initial_input in defn.get('initial_inputs', []):
                programs[name].in_queue.put(initial_input)

        # register program outputs as other programs inputs
        for name, defn in programs_definitions.items():
            for input_program in defn['input_from']:
                programs[input_program].register(programs[name])

        return programs

    def run(self):
        for name in self._programs:
            self._programs[name].start()

        for name in self._programs:
            self._programs[name].join()


if __name__ == '__main__':
    import sys

    with open(sys.argv[1], 'r') as f:
        programs_definitions = json.load(f)

    program_set = ProgramSet(programs_definitions)
    program_set.run()
