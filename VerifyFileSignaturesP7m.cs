using System;
using System.Collections;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Cms;
using Org.BouncyCastle.Cms;
using Org.BouncyCastle.Security.Certificates;
using iTextSharp.text;
using iTextSharp.text.exceptions;
using iTextSharp.text.pdf;
using iTextSharp.text.pdf.security;


namespace CriptografyLibrary
{

    public partial class VerifyFileSignatures
    {

        private SignaturesResult VerifyP7m(byte[] barr, string fileName)
        {
            //System.Diagnostics.Trace.WriteLine(string.Format("Verifica firme del file {0} ...",
                                                             //System.IO.Path.GetFileName(fileName)));
            var result = new SignaturesResult();
            result.SignatureInfos = new List<SignatureInfo>();
            try
            {
                var estensione = System.IO.Path.GetExtension(fileName).ToLower();
                var nomeFile = System.IO.Path.GetFileName(fileName);
                while (estensione == ".p7m")
                {
                    Org.BouncyCastle.Cms.CmsSignedData cms = new CmsSignedData(barr);
                    var certs = cms.GetCertificates("Collection");
                    var sis = cms.GetSignerInfos();
                    if (sis != null)
                    {
                        if (RecursiveP7m || ExtractSignedContent)
                        {
                            using (var ms = new MemoryStream())
                            {
                                cms.SignedContent.Write(ms);
                                barr = ms.ToArray();
                            }
                            if (ExtractSignedContent)
                                result.SignedContent = barr;
                        }

                        var signers = sis.GetSigners();
                        foreach (SignerInformation sign in signers)
                        {
                            var si = new SignatureInfo();

                            DateTime? dt = null;
                            var aaa = sign.SignedAttributes[CmsAttributes.SigningTime];
                            if (aaa != null && aaa.AttrValues != null && aaa.AttrValues.Count > 0)
                            {
                                var st = aaa.AttrValues[0] as DerUtcTime;
                                if (st != null)
                                    dt = st.ToAdjustedDateTime();
                            }
                            if (dt == null)
                                throw new Exception("Impossibile ricavare SignDateTime.");
                            si.SignDateTime = dt.Value;

                            //si.FilterSubtype=
                            IList ccc = new ArrayList(certs.GetMatches(null));
                            List<Org.BouncyCastle.X509.X509Certificate> list =
                                new List<Org.BouncyCastle.X509.X509Certificate>();
                            foreach (var c in ccc)
                            {
                                list.Add(c as Org.BouncyCastle.X509.X509Certificate);
                            }
                            var errors =
                                iTextSharp.text.pdf.security.CertificateVerification.VerifyCertificates(
                                    list, keyStore, si.SignDateTime);
                            if (errors.Count > 0)
                            {
                                si.ChainCertificatesNotValidAtSignedTime = true;
                            }

                            IList cs = new ArrayList(certs.GetMatches(sign.SignerID));
                            var cc = (Org.BouncyCastle.X509.X509Certificate)cs[0];
                            si.DigestAlgorithm = cc.SigAlgName;
                            //si.EncryptionAlgorithm = sign.EncryptionAlgorithmID.ToString();
                            si.IntegrityValid = sign.Verify(cc);

                            X509Certificate2 cert2 = new X509Certificate2(cc.GetEncoded());
                            si.Name = null;
                            si.Signer = cert2.SubjectName.Name;
                            si.Revision = sign.Version;
                            if (CheckRevocation)
                            {
                                try
                                {
                                    //si.CertificateRevocatedAtSignedTime = pkcs7.IsRevocationValid();
                                    List<Org.BouncyCastle.Ocsp.BasicOcspResp> ocsps =
                                        new List<Org.BouncyCastle.Ocsp.BasicOcspResp>();
                                    //if (cc.Ocsp != null)
                                    //    ocsps.Add(pkcs7.Ocsp);
                                    iTextSharp.text.pdf.security.OcspVerifier ocspVerifier = new OcspVerifier(null,
                                                                                                              ocsps);
                                    var issueCert =
                                        keyStore.SingleOrDefault(
                                            c => c.SubjectDN.Equals(cc.IssuerDN));
                                    if (issueCert == null)
                                        throw new Exception("Issuer certificate not found.");
                                    List<VerificationOK> verification = ocspVerifier.Verify(
                                        cc,
                                        issueCert,
                                        si.SignDateTime);
                                    if (verification.Count == 0)
                                    {
                                        var crls = new List<Org.BouncyCastle.X509.X509Crl>();
                                        CrlVerifier crlVerifier = new CrlVerifier(null, crls);
                                        crlVerifier.OnlineCheckingAllowed = true;
                                        verification = crlVerifier.Verify(cc, issueCert,
                                                                          si.SignDateTime);
                                    }
                                    if (verification.Count == 0)
                                    {
                                        si.CertificateRevocatedAtSignedTime = null;
                                    }
                                    else
                                    {
                                        si.CertificateRevocatedAtSignedTime = false;
                                        foreach (var verificationOk in verification)
                                        {
                                            System.Diagnostics.Trace.WriteLine(verificationOk);
                                        }
                                    }
                                }
                                catch (Exception ex)
                                {
                                    si.CertificateRevocatedAtSignedTime = true; // o null?
                                    System.Diagnostics.Trace.WriteLine(
                                        string.Format(
                                            "Si è verificato il seguente errore durante la verifica di revoca per la firma {2}  del file {0} {1}",
                                            System.IO.Path.GetFileName(fileName), ex.Message, si.Revision));
                                }

                            }
                            si.SignatureValid = si.IntegrityValid
                                                && !si.ChainCertificatesNotValidAtSignedTime
                                                && (!CheckRevocation || !si.CertificateRevocatedAtSignedTime.GetValueOrDefault(true));

                            result.SignatureInfos.Add(si);
                        }
                    }

                    if (!RecursiveP7m)
                        break;

                    nomeFile = System.IO.Path.GetFileNameWithoutExtension(nomeFile);
                    estensione = System.IO.Path.GetExtension(nomeFile);
                }

                result.SignaturesValid = result.SignatureInfos.All(si => si.SignatureValid);

                //System.Diagnostics.Trace.WriteLine(string.Format(
                //    "Verifica firme del file {0} completata con esito {1}", System.IO.Path.GetFileName(fileName),
                //    result.SignaturesValid ? "Positivo" : "Negativo"));
            }
            catch (Exception exx)
            {
                System.Diagnostics.Trace.WriteLine(
                    string.Format(
                        "Si è verificato il seguente errore durante la verifica delle firme del file {0} {1}",
                        System.IO.Path.GetFileName(fileName), exx.Message));
                throw exx;
            }

            return result;
        }


    }
}
