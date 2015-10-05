using System;
using System.Net;
using System.IO;

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

        public static int CountLines(string path)
        {
            int lines = 0;
            char[] buffer = new char[4096];

            using (StreamReader reader = new StreamReader(path))
            {
                while (!reader.EndOfStream)
                {
                    reader.ReadBlock(buffer, 0, buffer.Length);

                    for (int i = 0; i < buffer.Length; i++)
                    {
                        if (buffer[i] == '\n')
                            lines++;
                    }
                }
            }

            return lines;
        }

        public static int CalculateSampleSize(int N, double z = 1.96, double p = 0.5, double e = 0.05)
        {
            return (int)Math.Round(z * z * p * (1 - p) + (N - 1) * e * e);
        }
    }
}

