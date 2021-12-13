#!/bin/bash

#MIT License
#
#Copyright (c) 2021 Grégory Widmer
#
#Permission is hereby granted, free of charge, to any person obtaining a copy
#of this software and associated documentation files (the "Software"), to deal
#in the Software without restriction, including without limitation the rights
#to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
#copies of the Software, and to permit persons to whom the Software is
#furnished to do so, subject to the following conditions:
#
#The above copyright notice and this permission notice shall be included in all
#copies or substantial portions of the Software.
#
#THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
#IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
#FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
#AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
#LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
#OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
#SOFTWARE.

# Contact : gregory dot widmer at gwidmer dot fr
# Requirements : vim (for xxd), zip, openssl, awk

# Decimal to hex, with complete bytes :)
function toHex() {
  if [ "$#" -lt 1 ]; then
    return 1
  fi

  padding="${2:-0}"
  data=""
  if [ "$padding" -ne 0 ]; then
    data="$(printf "%0${padding}X" "$1")"
  else
    data="$(printf "%X" "$1")"
  fi
  [ "$((${#data} % 2))" -ne 0 ] && data="0$data"
  echo "$data"
  return 0
}

# BE-LE/LE-BE function
function reverseEndian() {
  str="$(echo "$1" | tr -d '[:space:]')"
  marker=0
  if [ $((${#str} % 2)) -eq 0 ]; then
    len=${#str}
  else
    len=$((${#str} + 1))
    marker=1
  fi

  data=""
  for pos in $(seq "$len" -2 0); do
    if [ "${#data}" -eq 0 ]; then
      if [ "$marker" -eq 1 ]; then
        data="0${str:$pos:1}"
      else
        data="${str:$pos:2}"
      fi
    else
      data+="${str:$pos:2}"
    fi
  done

  echo "$data" | tr -d '[:blank:]' | sed 's/.\{2\}/& /g'
  return 0
}

# Hex to binary
function hexToBinary() {
  if [ $# -ne 1 ]; then
    return 1
  fi
  str=$(echo "$1" | tr -d '[:blank:]')

  if ! echo "$str" | grep -E "^[[:xdigit:]]*$" >/dev/null; then
    return 1
  fi

  for ((i = 0; i < "${#str}"; i++)); do
    c="${str:$i:1}"
    number="$((16#$c))"
    for j in 8 4 2 1; do
      if [ $number -ge $j ]; then
        echo -n "1"
        number="$((number - j))"
      else
        echo -n "0"
      fi

    done
    echo -n " "
  done

  return 0
}

# Pad $1 with $2 $3 (For exemple, padWith "123" "4" "0" will print "0000123")
function padWith() {
  if [ "$#" -ne 3 ]; then
    return 1
  fi

  for i in $(seq 1 "$2"); do
    echo -n "$3"
  done

  echo "$1"
  return 0
}

# Swaps groups of 7 bits
function swapVarInt() {
  if [ $# -ne 1 ]; then
    return 1
  fi
  str=$(echo "$1" | tr -d '[:blank:]')

  if ! echo "$str" | grep -E "^[01]*$" >/dev/null; then
    return 1
  fi

  modulusSeven="$((${#str} % 7))"
  padLen="$((7 - modulusSeven))"

  if [ "$modulusSeven" -ne 0 ]; then
    testingStr="$(padWith "" "$modulusSeven" "0")"
    if [ "${str:0:$modulusSeven}" == "$testingStr" ]; then
      paddedBin+="${str:$modulusSeven:$((${#str}-modulusSeven))}"
    else
      paddedBin+="$(padWith "" "$padLen" "0")"
      paddedBin+="$str"
    fi
  else
    paddedBin+="$str"
  fi

  rtnBin=""
  for i in $(seq "${#paddedBin}" -7 0); do
    rtnBin+="${paddedBin:$i:7}"
  done

  echo "$rtnBin"
  return 0
}

# Returns a ProtoBuf Varint in Hex format (input : Hex)
function toVarIntHex() {
  if [ $# -ne 1 ]; then
    return 1
  fi
  str=$(echo "$1" | tr -d '[:blank:]')

  if ! echo "$str" | grep -E "^[[:xdigit:]]*$" >/dev/null; then
    return 1
  fi

  # Need complete bytes here
  if [ "$((${#str} % 2))" -ne 0 ]; then
    return 1
  fi

  binData=$(swapVarInt "$(hexToBinary "$str")")
  binRtnValue=""

  endPos="$((${#binData} - 1))"
  for pos in $(seq 0 7 "$endPos"); do
    subStr="${binData:$pos:7}"
    [ "$((pos + 7))" -ge "${#binData}" ] && binRtnValue+="0" || binRtnValue+="1"
    binRtnValue+="$subStr"
  done

  decimalRtnValue="$((2#$binRtnValue))"
  hexRtnValue="$(printf "%0$((${#binRtnValue} / 4))x" "$decimalRtnValue")"

  echo "$hexRtnValue" | tr -d '[:blank:]' | sed 's/.\{2\}/& /g'
  return 0
}

if [ $# -lt 2 ]; then
  echo "Required at least 2 arguments, $# provided."
  echo "Usage : ./$0 <Input folder> <Private key PEM> [Output file]"
  exit 1
fi

# Constants
MAGIC_NUMBER_CRX_HEX="43 72 32 34"
VERSION_CRX_HEX="03 00 00 00"

inputFolder=$1
privateKey=$2
outputFile="${4:-extension.crx}"

# First : Zip data
trap 'rm -f tmp.zip' EXIT
workingDir=$(pwd)
cd "$inputFolder" || exit 1
zip -q9rX "${workingDir}/tmp.zip" ./*
cd "$workingDir" || exit 1

keyType="NONE"
# Detect private key format
opensslKeyInfo=$(openssl pkey -noout -text -inform PEM -in <(cat <<<"$privateKey"))

echo "$opensslKeyInfo" | grep -q "RSA" && keyType="RSA"
echo "$opensslKeyInfo" | grep -q "ASN1" && keyType="ECC"

if [ "$keyType" == "NONE" ]; then
  echo 'Unsupported key type'
  exit 1
fi

trap 'rm -f key.tmp' EXIT
echo "$privateKey" >key.tmp

openssl pkey -pubout -outform DER -in key.tmp > pub.key

publicKeySize="$(ls -l 'pub.key' | awk '{print  $5}')"
echo "Public key length : $publicKeySize"

echo "Computing ProtoBuf 2 Headers..."
SIGNATURE_STR="43 52 58 33 20 53 69 67 6E 65 64 44 61 74 61 00" # Value : CRX3 SignedData\x00
PROTOBUF2_RSA_KEY_PROOF="12" # Field : 2 - Wire type : 2
PROTOBUF2_ECC_KEY_PROOF="1A" # Field : 3 - Wire type : 2
PROTOBUF2_SIGNATURE_HEADER="12" # Field : 2 - Wire type : 2
PROTOBUF2_PUBLIC_KEY_HEADER="0A" # Field : 1 - Wire type : 2
PROTOBUF2_SIGNED_DATA_HEADER="82 F1 04 12" # Field : 10 000 - Wire type : 2
PROTOBUF2_SIGNED_DATA_CRX_ID_HEADER="0A 10"

publicKeyHash="$(openssl dgst -sha256 -r < pub.key | cut -c 1-32)"
signedData="$(echo "$PROTOBUF2_SIGNED_DATA_CRX_ID_HEADER $publicKeyHash" | tr -d '[:space:]')"

proofPKHeader="$PROTOBUF2_PUBLIC_KEY_HEADER $(toVarIntHex "$(toHex "$publicKeySize")")"
echo "Public key header : 0x$proofPKHeader"
proofPK=$(echo "$proofPKHeader $(xxd -ps pub.key)" | tr -d '[:space:]' | tr -d '\n')
proofPKSize="$(((${#proofPK} / 2) + (${#proofPK} % 2)))"
echo "New public key length with header : $proofPKSize"

signedHeaderSize="$(reverseEndian "$(toHex "$((${#signedData} / 2))" 8)")"
(
  echo "$SIGNATURE_STR $signedHeaderSize $signedData" | xxd -r -p
  cat tmp.zip
) > to_sign.bin


openssl sha256 -sha256 -sign key.tmp -binary < to_sign.bin > sig.sha

rm -f key.tmp

signatureHeader="$PROTOBUF2_SIGNATURE_HEADER $(toVarIntHex "$(toHex 256)")"
echo "Signature Header : 0x$signatureHeader"

sigData=$(echo "$signatureHeader $(xxd -ps sig.sha)" | tr -d '[:space:]' | tr -d '\n')
sigLength="$(((${#sigData} / 2) + (${#sigData} % 2)))"
echo "New signature length with header : $sigLength"

globalHeader=""
case "$keyType" in
"RSA")
  globalHeader+="$PROTOBUF2_RSA_KEY_PROOF"
;;
"ECC")
  globalHeader+="$PROTOBUF2_ECC_KEY_PROOF"
;;
esac

globalHeaderLength="$((proofPKSize + sigLength))"
globalHeader+=" $(toVarIntHex "$(toHex "$globalHeaderLength")")"

echo "Global header : 0x$globalHeader"

globalHeaderData=$(echo "$globalHeader $proofPK $sigData $PROTOBUF2_SIGNED_DATA_HEADER $signedData" | tr -d '[:space:]')
crxHeaderLength="$(((${#globalHeaderData} / 2) + (${#globalHeaderData} % 2)))"

echo "CRX Header length : $crxHeaderLength - 0x$(toHex "$crxHeaderLength" 8)"
crxHeaderLength=$(reverseEndian "$(toHex "$crxHeaderLength" 8)")
echo "Writing CRX file : $outputFile"
# Writing header
(
  echo "$MAGIC_NUMBER_CRX_HEX $VERSION_CRX_HEX $crxHeaderLength $globalHeaderData" | xxd -r -p
  cat tmp.zip
) >"$outputFile"

echo "Wrote file $outputFile
Cleaning files..."
rm -f tmp.zip key.tmp pub.key sig.sha to_sign.bin
