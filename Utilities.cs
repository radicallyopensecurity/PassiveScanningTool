using System;
using System.Net;

namespace PassiveScanning
{
    public static class Utilities
    {
        public static IPAddress Increment(this IPAddress ipAddress)
        {
            byte[] bytes = ipAddress.GetAddressBytes();

            for (int i = 3; i >= 0; i--)
            {
                byte output;
                byte carry;

                Increment(bytes[i], out output, out carry);
                bytes[i] = output;

                if (carry == 0)
                    break;

                if (i == 0 && carry != 0)
                    throw new OverflowException();
            }

            return new IPAddress(bytes);
        }

        public static void Increment(byte input, out byte output, out byte carry)
        {
            if (input + 1 >= 255)
            {
                output = 0;
                carry = 1;
            }
            else
            {
                output = (byte)(input + 1);
                carry = 0;
            }
        }
    }
}

