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
  return ', '.join('0x{:02x}'.format(x) for x in packetBytes)

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

def countTrailingZeros(number):
  require(number > 0)
  result=0;
  while(number & 1<<result == 0):
    result += 1
  return result

def getNextLargerSize(lengthBits):
  if lengthBits<=8:
    return 8
  elif lengthBits<=16:
    return 16
  elif lengthBits<=32:
    return 32
  elif lengthBits<=64:
    return 64
  else:
    raise AssertionError("No field large enough for length "+str(lengthBits)+" bits")

def cTypeForBits(lengthBits):
  # TODO Figure out how to detect fields that need unsigned integers.
  lengthBits = int(lengthBits)
  require(lengthBits>0)
  if lengthBits==1:
    return 'bool'
  else:
    return 'uint'+str(getNextLargerSize(lengthBits))+'_t'

def cNameForField(field):
  return field.attrib['name'].split('.')[-1]

def cPacketTypeName(thisPacket):
  """
    Converts a packet with a messageid attribute and a showname like so:
      ".... 1011 = messageId: Announce Message (0xb)"
    to the string "AnnounceMessage"
  """
  showname = thisPacket.findall("./field[@name='ptp.v2.messageid']")[0].attrib['showname']
  spacedName = bitmaskRE.match(showname).group(3).split('(')[0].strip()
  return spacedName.title().replace(' ','').replace('_','')

def cTypeForPacket(thisPacket):
  result="typedef struct {\n";
  for field in thisPacket.iter('field'):
    if not len(list(field)):
      result += "    "+cTypeForBits( field.attrib['lengthBits']) + " " + cNameForField(field) + ";\n"
  result += "} " +cPacketTypeName(thisPacket)+ ";\n"
  return result;
    

def cDecodeField(field, packetStartPos):
  lengthBits = int(field.attrib['lengthBits'])
  fieldOffset = int(field.attrib['pos'])-packetStartPos;
  if fieldLooksLikeBitmask(field):
    sizeBytes = int(field.attrib['size'])
    # Output along the lines of:
    # bool unicast = be16toh((*(uint16_t *)&sampleMessage[48-42]) & 0x2000) ? true : false;
    bitmaskSize = getNextLargerSize(sizeBytes*8)
    result = "result."+cNameForField(field)+" = "
    result += "be"+str(bitmaskSize)+"toh((*(uint"+str(bitmaskSize)+"_t *)&bytes["+str(fieldOffset)
    result += "]) & "+field.attrib['bitmask']+")"
    if lengthBits==1:
      result += " ? true : false;"
    else:
      shift=countTrailingZeros(int(field.attrib['bitmask'], 16))
      if (shift > 0):
        result += ">>"+str(shift);
      result += ";"
    return result
  else:
    # Output along the lines of:
    # uint64_t ns = be64toh(*(uint64_t *)&sampleMessage[50-42])>>16 & 0xFFFFFFFFFFFF;
    require(lengthBits>=8)
    refSize = getNextLargerSize(lengthBits)
    result = "result."+cNameForField(field)+" = "
    result += "be"+str(refSize)+"toh(*(uint"+str(refSize)+"_t *)&bytes["+str(fieldOffset)+"])"
    rightShift = refSize-lengthBits
    if rightShift > 0:
      maskVal = (1<<lengthBits)-1
      result += ">>"+str(rightShift)+" & 0x"+'{:x}'.format(maskVal)
    result += ";"
    return result

def cDecoderForPacket(thisPacket):
  packetStartPos = int(thisPacket.attrib['pos'])
  for field in thisPacket.iter('field'):
    if not len(list(field)):
      print cDecodeField(field, packetStartPos)

shownameToBitmask(thisPacket)
fieldsToLengthBits(thisPacket)
#ET.dump( thisPacket )

print cTypeForPacket(thisPacket)
print cDecoderForPacket(thisPacket)
