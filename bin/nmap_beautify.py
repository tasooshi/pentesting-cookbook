#!/usr/bin/env python

import argparse

from xml.etree import ElementTree


GREEN = '\033[1;32m'
YELLOW = '\033[1;33m'
NONE = '\033[0m'


def parse_xml(xml_root):
    results = dict()
    for host in xml_root.findall('./host'):
        ports_dict = {}
        for port in host.findall('./ports/port'):
            if port.find('./state').attrib['state'] == 'open':
                attrs = [
                    port.attrib['protocol'],
                ]
                if port.find('./service') is not None:
                    srv = port.find('./service')
                    att = ['product', 'version', 'extrainfo']
                    extra = [srv.attrib[a] for a in att if a in srv.attrib]
                    service = srv.attrib['name']
                    if extra:
                        service += ' (' + ' '.join([srv.attrib[a] for a in att if a in srv.attrib]) + ')'
                    attrs.append(service)
                ports_dict[port.attrib['portid']] = attrs
        if ports_dict:
            ip = host.find('./address[@addrtype="ipv4"]').attrib['addr']
            try:
                os = host.find('./os/osmatch').attrib['name']
            except AttributeError:
                try:
                    os = host.find('.//elem[@key="os"]').text
                except AttributeError:
                    os = '?'
            results[ip] = {
                'ports': ports_dict,
                'os': os,
            }
    return results


if __name__ == '__main__':

    parser = argparse.ArgumentParser(description='Makes Nmap\'s XML output more digestible.')
    parser.add_argument('filename', help='E.g. output.xml')
    parser.add_argument('--csv', help='CSV output', action='store_true')
    args = parser.parse_args()

    tree = ElementTree.parse(args.filename)
    results = parse_xml(tree.getroot())
    if args.csv:
        for item, attrs in results.items():
            for port, details in attrs['ports'].items():
                try:
                    fingerprint = details[1]
                except IndexError:
                    fingerprint = '(?)'
                finally:
                    cols = [item, port, details[0], attrs['os'], fingerprint]
                    print(','.join(cols))
    else:
        for item, attrs in results.items():
            print('\n' + GREEN + item + NONE + ' (' + attrs['os'] + ')')
            for port, details in attrs['ports'].items():
                try:
                    fingerprint = details[1]
                except IndexError:
                    fingerprint = '(?)'
                finally:
                    print(YELLOW + port + NONE + '/' + details[0] + ': ' + fingerprint)
