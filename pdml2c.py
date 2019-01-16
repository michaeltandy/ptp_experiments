#!/usr/bin/python

import xml.etree.ElementTree as ET
import sys
import re

def require(mustBeTrue):
  if not mustBeTrue:
    raise AssertionError("Requirement was not true :(")

tree = ET.parse('xml-announce-message.pdml')

thisPacket = tree.findall("./packet/proto[@name='ptp']")[0]



def packetTreeToHexString(thisPacket):
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
  return ''.join('{:02x}'.format(x) for x in packetBytes)

# Wireshark:  0b02004000000000000000000000000000000000382c4afffee82e1d0001000005010000000000000000000000240080f8feffff80382c4afffee82e1d0000a0
# Code above: 0b02004000000000000000000000000000000000382c4afffee82e1d0001000005010000000000000000000000240080f8feffff80382c4afffee82e1d0000a0


def fieldsByByte(thisPacket):
  packetSizeBytes = int(thisPacket.attrib['size'])
  packetStartPos = int(thisPacket.attrib['pos'])
  fieldsByByte = [[] for i in range(0,packetSizeBytes)]

  for field in thisPacket.findall('field'):
    fSize = int(field.attrib['size'])
    fPos = int(field.attrib['pos'])-packetStartPos;
    for idx in range(fSize, 0, -1):
      fieldsByByte[fPos+idx-1].append(field)
      
  for counter, value in enumerate(fieldsByByte):
    if len(value) == 0:
      print "No entries for index", counter
  print fieldsByByte;

bitmaskRE = re.compile('^((?:[.10]{4} )+)=(.*):(.*)$')
def fieldLooksLikeBitmask(field):
  if 'showname' not in field.attrib:
    return False
  reMatch = bitmaskRE.match(field.attrib['showname'])
  if reMatch is None:
    return False
  require("unmaskedvalue" in field.attrib)
  return "." in reMatch.group(1)

def generateMaskForField(field):
  reMatch = bitmaskRE.match(field.attrib['showname'])
  maskString = reMatch.group(1).replace(' ','').replace('0','1').replace('.','0')
  mask = int(maskString, 2)
  return mask;

def shownameToBitmask(thisPacket):
  """
  Generates a bitmask from a PDML text representation. For example:
    .... .... ..0. .... = FREQUENCY_TRACEABLE: False
  would produce bitmask 0x0020 = 0000 0000 0010 0000
  """
  for field in filter(lambda x: fieldLooksLikeBitmask(x), thisPacket.iter('field')):
    field.attrib['bitmask'] = hex(generateMaskForField(field))
    print "Field "+field.attrib['name']+" looks like a bitmask - "+field.attrib['bitmask']


def fieldsToLengthBits(thisPacket):
  """
  Calculates a field length, in bits. If a bitmask this is based on the
  'showname' field; if not it's based on the 'size' field.
  """
  for field in thisPacket.iter('field'):
    if fieldLooksLikeBitmask(field):
      reMatch = bitmaskRE.match(field.attrib['showname'])
      field.attrib['lengthBits'] = str(len(reMatch.group(1).replace(' ','').replace('.','')))
    elif 'size' in field.attrib:
      field.attrib['lengthBits'] = str(8*int(field.attrib['size']))
    else:
      raise AssertionError("Missing size on non-bitmask field "+field.attrib['name'])

def cTypeForBits(lengthBits):
  require(lengthBits>0)
  if lengthBits==1:
    return 'bool'
  elif lengthBits<=8:
    return 'uint8_t'
  elif lengthBits<=16:
    return 'uint16_t'
  elif lengthBits<=32:
    return 'uint32_t'
  elif lengthBits<=64:
    return 'uint64_t'
  else:
    raise AssertionError("No field large enough for length "+str(lengthBits)+" bits")

shownameToBitmask(thisPacket)
fieldsToLengthBits(thisPacket)
ET.dump( thisPacket )
