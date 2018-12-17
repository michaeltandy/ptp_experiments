#!/usr/bin/python

import xml.etree.ElementTree as ET
import sys

def require(mustBeTrue):
  if not mustBeTrue:
    raise AssertionError("Requirement was not true :(")

tree = ET.parse('xml-announce-message.pdml')

thisPacket = tree.findall("./packet/proto[@name='ptp']")[0]

ET.dump( thisPacket )

packetSizeBytes = int(thisPacket.attrib['size'])
packetStartPos = int(thisPacket.attrib['pos'])

packetBytes = bytearray(packetSizeBytes)

for field in thisPacket.findall('field'):
  fSize = int(field.attrib['size'])
  fPos = int(field.attrib['pos'])-packetStartPos;
  if 'unmaskedvalue' in field.attrib:
    require(len(field.attrib['unmaskedvalue']) <= 2*fSize)
    fUnmasked = int(field.attrib['unmaskedvalue'], 16)
    for idx in range(fSize, 0, -1):
      packetBytes[fPos+idx-1] = fUnmasked&0xFF
      fUnmasked=fUnmasked >> 8
  elif 'value' in field.attrib:
    require(len(field.attrib['value']) <= 2*fSize)
    fVal = int(field.attrib['value'], 16)
    for idx in range(fSize, 0, -1):
      packetBytes[fPos+idx-1] = fVal&0xFF
      fVal=fVal >> 8

print ''.join('{:02x}'.format(x) for x in packetBytes)

# Wireshark:  0b02004000000000000000000000000000000000382c4afffee82e1d0001000005010000000000000000000000240080f8feffff80382c4afffee82e1d0000a0
# Code above: 0b02004000000000000000000000000000000000382c4afffee82e1d0001000005010000000000000000000000240080f8feffff80382c4afffee82e1d0000a0
