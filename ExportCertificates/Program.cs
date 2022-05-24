using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;

namespace ExportCertificates
{
    internal class Program
    {

        [DllImport("msi.dll", CharSet = CharSet.Ansi, SetLastError = false)]
        static extern int MsiGetFileSignatureInformation(string fileName, int flags, out IntPtr certContext, IntPtr hashData, ref int hashDataLength);

        [DllImport("Crypt32.dll", CharSet = CharSet.Ansi, SetLastError = true)]
        static extern int CertFreeCertificateContext(IntPtr certContext);

        static void Main(string[] args)
        {
            if (args.Length < 2)
            {
                Console.WriteLine("Lost Parameter!");
                return;
            }

            string inputDirPath = args[0];
            if (!Directory.Exists(inputDirPath))
            {
                Console.WriteLine($"{inputDirPath}，Input Directory Path Invalid!");//判断文件夹是否存在
                return;
            }

            string destDirPath = args[1];
            if (!Directory.Exists(destDirPath))
            {
                try
                {
                    Directory.CreateDirectory(destDirPath);//新建目录
                }
                catch
                {
                    Console.WriteLine($"{destDirPath}，Destination Directory Path Invalid!");
                    return;
                }
            }

            string certNames = string.Empty;

            foreach (string fileName in Directory.GetFiles(inputDirPath))
            {
                Console.WriteLine("FileName:{0}", Path.GetFileName(fileName));

                IntPtr certContext = IntPtr.Zero;
                IntPtr hashData = IntPtr.Zero;
                int hashDataLength = 0;
                int result = MsiGetFileSignatureInformation(
                            fileName.ToString(),
                            0,
                            out certContext,
                            hashData,
                            ref hashDataLength);

                if (result == 0)
                {
                    X509Certificate2 cert = new X509Certificate2(certContext);
                    var byt = cert.Export(X509ContentType.Cert);
                    
                    if(!certNames.Contains(cert.Thumbprint))
                        certNames += $"{cert.Thumbprint}\n";

                    using (FileStream fs = new FileStream($@"{destDirPath}\{cert.Thumbprint}.cer",
            FileMode.Create))
                    {
                        BinaryWriter sr = new BinaryWriter(fs);
                        sr.Write(byt);
                        sr.Flush();
                        sr.Close();
                        fs.Close();
                    }
                    Console.WriteLine($"{cert.Thumbprint}.cer Exported");

                    CertFreeCertificateContext(certContext);
                }
            }

            //To Generate Organization.txt
            using (FileStream fs = new FileStream($@"{destDirPath}\Organization.txt",
            FileMode.Create))
            {
                StreamWriter sr = new StreamWriter(fs);
                sr.Write(certNames);
                sr.Flush();
                sr.Close();
                fs.Close();
            }

        }
    }
}