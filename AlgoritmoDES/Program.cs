using System.Collections;
using System.Text;

namespace AlgoritmoDES
{
    /// <summary>
    /// Applicativo Console di esempio per la criptare e decriptare un messaggio di 64 bit (8 caratteri) tramite l'algoritmo DES
    /// Maestri Tommaso - 5F, ITT B. Pascal - Cesena - 18/11/2022
    /// Bibliografia: https://page.math.tu-berlin.de/~kant/teaching/hess/krypto-ws2006/des.htm
    /// Siti Utili per effettuare verifiche: 
    /// - https://emvlab.org/descalc/ (Calcolatore DES, lavora solo con stringe esadecimali)
    /// - https://www.rapidtables.com/convert/number/ascii-to-hex.html (Conversione del testo ASCII in stringa esadecimale, e viceversa)
    /// </summary>
    internal class Program
    {
        //matrici di permutazione per le chiavi
        static int[] PC1 = { 57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18, 10, 2, 59, 51, 43, 35, 27, 19, 11, 3, 60, 52, 44, 36, 63, 55, 47, 39, 31, 23, 15, 7, 62, 54, 46, 38, 30, 22, 14, 6, 61, 53, 45, 37, 29, 21, 13, 5, 28, 20, 12, 4 };
        static int[] PC2 = { 14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10, 23, 19, 12, 4, 26, 8, 16, 7, 27, 20, 13, 2, 41, 52, 31, 37, 47, 55, 30, 40, 51, 45, 33, 48, 44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32 };
        
        //matrice di espansione per il blocco in ingresso nella funzione F
        static int[] E = { 32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9, 8, 9, 10, 11, 12, 13, 12, 13, 14, 15, 16, 17, 16, 17, 18, 19, 20, 21, 20, 21, 22, 23, 24, 25, 24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32, 1 };

        //matrice di permutazione iniziale per il messaggio
        static int[] IP = { 58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4, 62, 54, 46, 38, 30, 22, 14, 6, 64, 56, 48, 40, 32, 24, 16, 8, 57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27, 19, 11, 3, 61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7 };

        //8 S-BOX
        static int[][,] SB = new int[8][,]
        {
            new int[4,16] {
                {14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7},
                {0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8},
                {4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0},
                {15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13}
            },
            new int[4,16]
            {
                {15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10},
                {3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5},
                {0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15},
                {13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9}
            },
            new int[4,16]
            {
                {10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8},
                {13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1},
                {13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7},
                {1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12}
            },
            new int[4,16]
            {
                {7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15},
                {13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9},
                {10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4},
                {3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14}
            },
            new int[4,16]
            {
                {2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9},
                {14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6},
                {4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14},
                {11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3}
            },
            new int[4,16]
            {
                {12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11},
                {10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8},
                {9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6},
                {4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13}
            },
            new int[4,16]
            {
                {4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1},
                {13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6},
                {1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2},
                {6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12}
            },
            new int[4,16]
            {
                {13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7},
                {1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2},
                {7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8},
                {2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11}
            }
        };

        //matrice di permutazione per il blocco in uscita dalla funzione F (dopo le S-BOX)
        static int[] P = new int[] { 16, 7, 20, 21, 29, 12, 28, 17, 1, 15, 23, 26, 5, 18, 31, 10, 2, 8, 24, 14, 32, 27, 3, 9, 19, 13, 30, 6, 22, 11, 4, 25 };

        //matrice di permutazione finale
        static int[] IPi = new int[] { 40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31, 38, 6, 46, 14, 54, 22, 62, 30, 37, 5, 45, 13, 53, 21, 61, 29, 36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27, 34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41, 9, 49, 17, 57, 25 };

        //dizionario che associa ad un numero decimale il valore corrispettivo in binario
        static Dictionary<int, bool[]> DecimalToBinary = new Dictionary<int, bool[]>()
        {
            { 0, new bool[] {false, false, false, false } },
            { 1, new bool[] {false, false, false, true } },
            { 2, new bool[] {false, false, true, false } },
            { 3, new bool[] {false, false, true, true } },
            { 4, new bool[] {false, true, false, false } },
            { 5, new bool[] {false, true, false, true } },
            { 6, new bool[] {false, true, true, false } },
            { 7, new bool[] {false, true, true, true } },
            { 8, new bool[] { true, false, false, false } },
            { 9, new bool[] { true, false, false, true } },
            { 10, new bool[] { true, false, true, false } },
            { 11, new bool[] { true, false, true, true } },
            { 12, new bool[] { true, true, false, false } },
            { 13, new bool[] { true, true, false, true } },
            { 14, new bool[] { true, true, true, false } },
            { 15, new bool[] { true, true, true, true } }
        };

        static void Main(string[] args)
        {

            string? msg = string.Empty;
            do
            {
                Console.Write("Testo da convertire (8 caratteri): ");
                msg = Console.ReadLine();
            } while (msg?.Length != 8);

            string? key = string.Empty;
            do
            {
                Console.Write("Chiave (8 caratteri): ");
                key = Console.ReadLine();
            } while (key?.Length != 8);

            //conversione della stringa in stringa esadecimale
            string msgHex = string.Join(string.Empty, msg.Select(c => ((int)c).ToString("X")).ToArray()); 
            string keyHex = string.Join(string.Empty, key.Select(c => ((int)c).ToString("X")).ToArray());

            //conversione della stringa esadecimale in array di bytes
            byte[] msgBytes = HexStringToByteArray(msgHex);
            byte[] keyBytes = HexStringToByteArray(keyHex);


            Console.WriteLine("\nMessaggio in HEX:");
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.WriteLine(Convert.ToHexString(msgBytes));
            Console.ForegroundColor = ConsoleColor.White;
            Console.WriteLine("\nChiave in HEX:");
            Console.ForegroundColor = ConsoleColor.DarkYellow;
            Console.WriteLine(Convert.ToHexString(keyBytes));
            Console.ForegroundColor = ConsoleColor.White;

            //trasformazione dell'array di bytes in array di bits
            BitArray msgBitArray = new BitArray(msgBytes);
            BitArray keyBitArray = new BitArray(keyBytes);

            //inversione dei bit nel BitArray (l'architettuta del processore salva il LSB a sinistra
            bool[] M = BitArrayToBoolArray(msgBitArray);
            bool[] K = BitArrayToBoolArray(keyBitArray);


            #region Gestione Chiavi

            //permutazione iniziale della chiave da 64bit a 56bit
            bool[] K56 = Permutation(K, PC1);

            //suddivisione in due blocchi da 28 bit la chiave
            bool[] C0 = K56.Take(K56.Length / 2).ToArray();
            bool[] D0 = K56.Skip(K56.Length / 2).ToArray();

            //shift verso sinistra dei blocchi
            (bool[], bool[])[] CD = new (bool[], bool[])[16];
            CD[0] = (LeftShift(C0, 1), LeftShift(D0, 1));

            for (int i = 1; i < CD.Length; i++)
            {
                if (i == 1 || i == 8 || i == 15)
                {
                    CD[i] = (LeftShift(CD[i - 1].Item1, 1), LeftShift(CD[i - 1].Item2, 1));
                }
                else
                {
                    CD[i] = (LeftShift(CD[i - 1].Item1, 2), LeftShift(CD[i - 1].Item2, 2));
                }
            }

            bool[][] K48 = new bool[16][];

            //concatenazione dei blocchi a coppie e permutazione per ottenere 16 chiavi da 48 bit
            for (int i = 0; i < K48.Length; i++)
            {
                K48[i] = Permutation(CD[i].Item1.Concat(CD[i].Item2).ToArray(), PC2);
            }

            #endregion

            #region Gestione Messaggio

            //permutazione iniziale del messaggio
            M = Permutation(M, IP);

            //divisione nei due blocchi di Sinistra e Destra
            bool[] L0 = M.Take(M.Length / 2).ToArray();
            bool[] R0 = M.Skip(M.Length / 2).ToArray();
            (bool[], bool[]) L16R16;

            ConsoleKey tastoPremuto;
            do
            {
                Console.Write("\nIl testo inserito è da criptare o decriptare? (c/d): ");
                tastoPremuto = Console.ReadKey().Key;
            } while (tastoPremuto != ConsoleKey.C && tastoPremuto != ConsoleKey.D);

            bool enc = true;
            if (tastoPremuto == ConsoleKey.C)
                L16R16 = ApplySteps(L0, R0, K48);
            else
            {
                //per decriptare l'algoritmo è lo stesso ma le sottochiavi vengono usate in ordine inverso (step1 - subkey16, step2 - subkey15, ecc)
                L16R16 = ApplySteps(L0, R0, K48.Reverse().ToArray()); 
                enc = false;
            }

            //concatenazione dei due blocchi con scambio (L16 a destra e R16 a sinistra)
            bool[] bloccoFinale = L16R16.Item2.Concat(L16R16.Item1).ToArray();

            //permutazione finale
            bloccoFinale = Permutation(bloccoFinale, IPi);

            //conversione dell'array di bits in array di byte
            byte[] bytesOutput = BoolArrayToByteArray(bloccoFinale);

            //conversione in stringa dell'array di bytes
            string result = Encoding.UTF8.GetString(bytesOutput);

            Console.WriteLine("\n\nRisultato in HEX:");
            Console.ForegroundColor = ConsoleColor.DarkGreen;
            Console.WriteLine(Convert.ToHexString(bytesOutput));
            Console.ForegroundColor = ConsoleColor.White;
            Console.WriteLine("\nRisultato in stringa:");
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine(result);
            Console.ForegroundColor = ConsoleColor.White;

            Console.Write("\nVuoi svolgere il procedimento inverso? (y/n): ");
            if (Console.ReadKey().Key == ConsoleKey.Y)
            {
                //ripetizione degli step iniziali sul messaggio, fino all'applicazione degli step
                byte[] invBytes = HexStringToByteArray(Convert.ToHexString(bytesOutput));
                BitArray invBitArray = new BitArray(invBytes);
                bool[] invM = BitArrayToBoolArray(invBitArray);
                invM = Permutation(invM, IP);

                bool[] invL0 = invM.Take(invM.Length / 2).ToArray();
                bool[] invR0 = invM.Skip(invM.Length / 2).ToArray();
                (bool[], bool[]) invL16R16;

                if (!enc)
                    invL16R16 = ApplySteps(invL0, invR0, K48);
                else
                    invL16R16 = ApplySteps(invL0, invR0, K48.Reverse().ToArray()); //se deve decriptare le chiavi vengono passate in ordine inverso

                //ripetizione degli step finali sul messaggio
                bool[] invBloccoFinale = invL16R16.Item2.Concat(invL16R16.Item1).ToArray();

                invBloccoFinale = Permutation(invBloccoFinale, IPi);

                byte[] invBytesOutput = BoolArrayToByteArray(invBloccoFinale);

                string invResult = Encoding.UTF8.GetString(invBytesOutput);

                Console.WriteLine("\n\nRisultato in HEX:");
                Console.ForegroundColor = ConsoleColor.DarkGreen;
                Console.WriteLine(Convert.ToHexString(invBytesOutput));
                Console.ForegroundColor = ConsoleColor.White;
                Console.WriteLine("\nRisultato in stringa:");
                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine(invResult);
                Console.ForegroundColor = ConsoleColor.White;
            }

            #endregion
        }

        public static byte[] HexStringToByteArray(string hex)
        {
            return Enumerable.Range(0, hex.Length)
                             .Where(x => x % 2 == 0)
                             .Select(x => Convert.ToByte(hex.Substring(x, 2), 16))
                             .ToArray();
        }

        //per debug
        public static void PrintBoolArray(bool[] bits, string title)
        {
            Console.WriteLine("\n" + title);
            foreach (bool bit in bits)
            {
                Console.Write(bit ? 1 : 0);
            }
            Console.WriteLine();
        }

        public static byte[] BoolArrayToByteArray(bool[] bits)
        {
            byte[] bytes = new byte[bits.Length / 8];
            for (int i = 0; i < bits.Length; i += 8)
            {
                int value = 0;
                for (int j = 0; j < 8; j++)
                {
                    if (bits[i + j])
                    {
                        value += 1 << (7 - j);
                    }
                }
                bytes[i / 8] = (byte)value;
            }
            return bytes;
        }

        //calcolo dei 16 step
        public static (bool[], bool[]) ApplySteps(bool[] L0, bool[] R0, bool[][] subkeys)
        {
            bool[] L = L0;
            bool[] R = R0;
            (bool[], bool[]) Blocchi = (L0, R0);
            for (int i = 0; i < 16; i++)
            {
                Blocchi = Step(Blocchi.Item1, Blocchi.Item2, subkeys[i]);
            }

            return Blocchi;
        }

        //applicazione del singolo step
        public static (bool[], bool[]) Step(bool[] L, bool[] R, bool[] subkey)
        {
            //il blocco di destra, diventa il blocco di sinistra del prossimo step
            bool[] L1 = R; 
            //il blocco di destra del prossimo step si ottiene dallo XOR tra il blocco di sinistra e l'output della funzione F
            bool[] R1 = XOR(L, F(R, subkey)); 

            (bool[], bool[]) tuplaRisultati = (L1, R1);
            return tuplaRisultati;
        }

        public static bool[] F(bool[] R, bool[] K)
        {
            bool[] RxorK = XOR(Expand(R), K);

            //divisione dell'output dello XOR in 8 sottoblocchi da 6 bit
            bool[][] sottoblocchiIn = Split(RxorK, 6);

            bool[][] sottoblocchiOut = new bool[sottoblocchiIn.Length][];

            //compressione dei sottoblocchi da 6 bit in sottoblocchi da 4 bit tramite le S-Box
            for (int i = 0; i < sottoblocchiIn.Length; i++)
            {
                sottoblocchiOut[i] = SBox(sottoblocchiIn[i], i);
            }

            //concatenazione dei sottoblocchi da 4 bit in un unico blocco da 32 bit
            bool[] R1 = sottoblocchiOut[0];
            for (int i = 1; i < sottoblocchiOut.Length; i++)
            {
                R1 = R1.Concat(sottoblocchiOut[i]).ToArray();
            }

            //permutazione sul blocco in uscita dalla funzione F
            R1 = Permutation(R1, P);

            return R1;
        }

        public static bool[] SBox(bool[] block, int i)
        {
            /* qui ho avuto un po' di problemi estrare i singoli bit dal blocco e convertirli in int in modo da usarli come indice di matrice nella S-BOX
            *  tutti i false a inizio array servono perché il metodo ToInt32 richiede 4 byte
            *  il .Reverse() alla fine serve per risolvere la problematica riguardante la posizione dei bit più significativi
            *  (avrei potuto scrivere l'array al contrario e non fare il reverse, ma visto che così funziona non lo cambio)
            */
            int row = BitConverter.ToInt32(BoolArrayToByteArray(new bool[] { false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, block[0], block[5] }).Reverse().ToArray(), 0);
            int col = BitConverter.ToInt32(BoolArrayToByteArray(new bool[] { false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, block[1], block[2], block[3], block[4] }).Reverse().ToArray(), 0);
            int val = SB[i][row, col];
            bool[] blockOut = DecimalToBinary[val]; //per la conversione decimale->binario uso un dizionario che è il metodo più comodo
            return blockOut;
        }

        //splitta un blocco da 48 bit in 8 sottoblocchi da 6 bit ciascuno (per l'input delle S-BOX)
        public static bool[][] Split(bool[] arr, int size)
        {
            bool[][] splitArr = new bool[8][];
            for (int i = 0; i < arr.Length / size; i++)
            {
                splitArr[i] = arr.Skip(i * size).Take(size).ToArray();
            }
            return splitArr;
        }

        //applica la matrice di espansione E al blocco da 32bit in entrata nella funzione F, rendendolo a 48 bit
        public static bool[] Expand(bool[] R)
        {
            bool[] ER = new bool[E.Length];

            for (int i = 0; i < ER.Length; i++)
            {
                ER[i] = R[E[i] - 1];
            }

            return ER;
        }

        //shifta i bits dell'array a sinistra di <pos> posizioni
        public static bool[] LeftShift(bool[] bits, int pos)
        {
            bool[] result = new bool[bits.Length];

            for (int j = 0; j < pos; j++)
            {
                for (int i = 0; i < bits.Length - 1; i++)
                {
                    result[i] = bits[i + 1];
                }
                result[result.Length - 1] = bits[0];
                bits = new bool[result.Length];
                result.CopyTo(bits, 0);
            }

            return result;
        }

        //applica la matrice di permutazione <permutationMatrix> a <input>
        public static bool[] Permutation(bool[] input, int[] permutationMatrix)
        {
            bool[] result = new bool[permutationMatrix.Length];

            for (int i = 0; i < result.Length; i++)
            {
                result[i] = input[permutationMatrix[i] - 1];
            }

            return result;
        }

        //converte un BitArray in un array di bool invertendo le posizioni (per cambiare la posizione dei bit significativi)
        public static bool[] BitArrayToBoolArray(BitArray bitArray)
        {
            bool[] bits = new bool[64];

            for (int i = 0; i < 8; i++)
            {
                for (int j = 7; j >= 0; j--)
                {
                    bits[(i * 8) + (7 - j)] = (bitArray[(8 * i) + j]);
                }
            }

            return bits;
        }

        //calcolo dello XOR tra i due array
        public static bool[] XOR(bool[] bits1, bool[] bits2)
        {
            bool[] output = new bool[bits1.Length];

            if (bits1.Length == bits2.Length)
            {
                for (int i = 0; i < output.Length; i++)
                {
                    output[i] = bits1[i] ^ bits2[i];
                }
            }
            else
            {
                throw new Exception("tentativo di XOR tra array di dimensioni diverse");
            }
            return output;
        }
    }

}
