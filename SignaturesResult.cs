using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace CriptografyLibrary
{
    public class SignaturesResult
    {
        //public string PdfVersion { get; set; }

        public List<SignatureInfo> SignatureInfos { get; set; }

        public bool SignaturesValid { get; set; }

        public byte[] SignedContent { get; set; }

        public string SignedContentType { get; set; }

        //public string ErrorMessage { get; set; }
    }
}
