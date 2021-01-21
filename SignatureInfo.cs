using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace CriptografyLibrary
{
    public class SignatureInfo
    {
        public bool IntegrityValid { get; set; }
        public string Name { get; set; }
        public int Revision { get; set; }
        //public bool? SignCoverWholeDocument { get; set; }
        public string Signer { get; set; }
        public DateTime SignDateTime { get; set; }
        public string DigestAlgorithm { get; set; }
        //public int FilterSubtype { get; set; }
        //public DateTime? TimeStamp { get; set; }
        //public string TimeStampService { get; set; }
        //public bool? TimeStampVerified { get; set; }
        //public bool? ChainCertificatesExpiredAtSignedTime { get; set; }
        public bool ChainCertificatesNotValidAtSignedTime { get; set; }
        public bool? CertificateRevocatedAtSignedTime { get; set; }
        public bool SignatureValid { get; set; }
    }
}
