#!/usr/bin/env python3
'''
Examples from systems programming class
'''

import random
import sys
import gzip
import re
import os
import json
import requests

def lyrics (lyric: str="") -> dict:
    ''' counts letters

    doctest
    >>> lyrics(hi)
    {h:1, i:1}
    '''
    lyric  = "I finally know now what I should have known then That I could still be ruthless if you'll let me"
    counts = {}

    for letter in lyric.lower():
        counts[letter] = counts.get(letter, 0) + 1

    return counts


def main(arguments=sys.argv[1:], stream=sys.stdin):
    try:
        thing = str(arguments[0])
    except IndexError:
        thing = ""

    thing = str(arguments[0]) if len(arguments) >= 1 else ""

    # treat arguments as a queue
    # can also use for loop enumerate
    while arguments:
        arguments = arguments.pop(0)
        print(arguments)

    # to pass file name
    # for line in open(arguments[0]):
    # to pass zipped file name
    for line in gzip.open(arguments[0], 'rt'):
        line = line.rstrip()
        data = line.split()
        print(data)

    # to auto close file after
    # with gzip.open(arguments[0], 'rt') as stream:


    for line in os.popen('cowsay -l'):
        print(line.rstrip())

        os.system(f'cowsay -f {selected} {" ".join(sys.argv[1:])}')


    # can call popen on curl, get every line
    regex = r'/([^/]+)/[A-Z]'
    response = requests.get(url)
    for match in re.findall(regex, response.text):
        print(match)

    counts = {}
    # counts[letter] = counts.get(letter, 0) + 1


    # exam prep: translate pipelines to python
    for line in open('/etc/passwd'):
        username = line.split(':')[0]
        if username.endswith('d'):
            print(username)

    for line in csv.reader(open('/etc/passwd'), delimter=':'):
        if username[-1] == 'd':
            print(username)


    Person = collections.namedtuple('Person', 'first_name last_name')

    sortedPeople = sorted(People, key=lambda p: (p.last_name, p.first_name))



    scores = list(map(lambda student: sum(map(float, student)), csv.reader(data)))


    output = os.popen(command).read()
    re.findall(r'[0-9\.]+', output)


def problem1():
    # cat /etc/passwd | cut -d : -f 4 | sort | uniq -c | sort -rns | head -n 1 | awk '{print $2}'

    items = sorted(map(lambda x: x.split(':')[3], filter(lambda y: len(y) > 1, open('/etc/passwd'))))

    counts = {}

    for item in items:
        counts[item] = counts.get(item, 0) + 1

    sortedCounts = {k: v for k, v in sorted(counts.items(), key=lambda item: ' '.join([str(a) for a in item]), reverse=False)}

    for index, key in enumerate(sortedCounts):
        if index < 1:
            # print(f'{sortedCounts[key]:>7} {key}')
            print(f'{key}')


def problem2():
    # curl -sL https://yld.me/raw/g4gJ | sort -t , -k 3 | cut -d , -f 2 | tr a-z A-Z

    request = requests.get('https://yld.me/raw/g4gJ').text

    for thing in map(lambda b: b.upper(), map(lambda a: a.split(',')[1], sorted(filter(lambda y: len(y) > 1, request.split('\n')), key=lambda x: x.split(',')[2]))):
        print(thing)

def problem3():
    # cat /etc/passwd | cut -d : -f 3 | grep -E '^[0-9]{2}$' | sort | uniq

    # for thing in re.findall(r'^[0-9]{2}$', '\n'.join(list(map(lambda x: x.split(':')[2], filter(lambda y: len(y) > 1, open('/etc/passwd')))))):
    for thing in set(sorted(map(int, map(lambda x: x.split(':')[2], filter(lambda y: len(y) > 1, open('/etc/passwd')))))):
        if len(str(thing)) == 2:
            print(thing)

def problem4():
    # curl -sL http://yld.me/raw/lmz | cut -d , -f 2 | grep -Eo '^B.*' | sort

    request = requests.get('http://yld.me/raw/lmz').text

    for thing in sorted(filter(lambda x: x[0] == 'B', map(lambda y: y.split(',')[1], filter(lambda y: len(y) > 1, request.split('\n'))))):
        print(thing)


def others():
    # grep -Po ':1\d*0:' /etc/passwd | wc -l
    print(len(re.findall(r':1\d*0:', open('/etc/passwd').read())))


    # /bin/ls -ld /etc/* | awk '{print $4}' | sort | uniq
    text = os.popen('/bin/ls -ld /etc/*').read()
    mapped = sorted(list(set(map(lambda x: x.split()[3], filter(lambda y: len(y) > 1, text.split('\n'))))))


    # curl -sLk http://yld.me/raw/fDIO | cut -d , -f 4 | grep -Eo '^M.*' | sort
    url = 'http://yld.me/raw/fDIO'
    data = requests.get(url).text
    cutted = sorted(list(filter(lambda a: a[0] == 'M', map(lambda x: x.split(',')[3], filter(lambda y: len(y) > 1, data.split('\n'))))))


    # cat /etc/passwd | cut -d : -f 7 | sort | uniq -c | sort -srn
    result = sorted(list(map(lambda x: x.split(':')[6], filter(lambda y: len(y) > 1, open('/etc/passwd').read().split('\n')))))
    counts = {}
    for thing in result:
        counts[thing] = counts.get(thing,  0) + 1
    # potentially wrong sort
    sortedCounts = {k: v for k, v in sorted(counts.items(), key=lambda item: item[1], reverse=True)}

    for value, key in sortedCounts.items():
        print(f'{key:>7} {value}')


if __name__ == '__main__':
    # problem1()
    # problem2()
    # problem3()
    problem4()

    # main()
