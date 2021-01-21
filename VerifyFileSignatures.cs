using System;
using System.Collections;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.IO;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;
using iTextSharp.text;
using iTextSharp.text.exceptions;
using iTextSharp.text.pdf;
using iTextSharp.text.pdf.security;

namespace CriptografyLibrary
{

    public partial class VerifyFileSignatures
    {
        public bool CheckRevocation { get; set; }
        public bool ExtractSignedContent { get; set; }
        public bool RecursiveP7m { get; set; }

        private ICollection<Org.BouncyCastle.X509.X509Certificate> keyStore; 

        public VerifyFileSignatures()
        {
            CheckRevocation = false;
            ExtractSignedContent = false;
            RecursiveP7m = true;

            keyStore = new Collection<Org.BouncyCastle.X509.X509Certificate>();

            X509Store wStore=new X509Store(StoreName.Root, StoreLocation.LocalMachine);
            wStore.Open(OpenFlags.MaxAllowed);

            foreach (var certificate in wStore.Certificates)
            {
                var cert = Org.BouncyCastle.Security.DotNetUtilities.FromX509Certificate(certificate);    
                keyStore.Add(cert);
            }

            wStore.Close();
        }

        public SignaturesResult Verify(byte[] barr, string fileName)
        {
            if (string.IsNullOrEmpty(fileName))
                throw new Exception("fileName mancante");
            if (barr==null || barr.Length==0)
                throw new Exception("File mancante.");

            var ext = System.IO.Path.GetExtension(fileName);
            if (string.IsNullOrEmpty(ext))
                throw new Exception("Estensione file non determinabile");
            if (ext.ToLower() == ".pdf")
                return VerifyPdf(barr, fileName);
            if (ext.ToLower() == ".p7m")
                return VerifyP7m(barr, fileName);
            throw new NotSupportedException(ext);
        }

        private SignaturesResult VerifyPdf(byte[] barr, string fileName)
        {
            //System.Diagnostics.Trace.WriteLine(string.Format("Verifica firme del file {0} ...", System.IO.Path.GetFileName(fileName)));
            var result = new SignaturesResult();

            try
            {
                using (var reader = new PdfReader(barr))
                {
                    var fields = reader.AcroFields;
                    var sInfos = fields.GetSignatureNames();
                    if (sInfos.Count > 0) // è firmato
                    {
                        //System.IO.Stream stream = fields.ExtractRevision(sInfos[0]);
                        //using (var ms = new MemoryStream())
                        //{
                        //    stream.CopyTo(ms);
                        //    result.Content = ms.ToArray();
                        //}
                        result.SignatureInfos = new List<SignatureInfo>();
                        foreach (var sName in sInfos)
                        {
                            var si = new SignatureInfo()
                                {
                                    Name = sName
                                };
                            result.SignatureInfos.Add(si);
                            si.Revision = fields.GetRevision(sName);
                            //si.SignCoverWholeDocument = fields.SignatureCoversWholeDocument(sName);
                            var pkcs7 = fields.VerifySignature(sName);
                            //si.Signer = pkcs7.SignName;
                            si.Signer = new X509Certificate2(pkcs7.SigningCertificate.GetEncoded()).SubjectName.Name;
                            si.SignDateTime = pkcs7.SignDate;
                            si.IntegrityValid = pkcs7.Verify(); //TODO: DMP Settings? annotations?
                            si.SignatureValid = si.IntegrityValid
                                            && !si.ChainCertificatesNotValidAtSignedTime
                                            && (!CheckRevocation || !si.CertificateRevocatedAtSignedTime.GetValueOrDefault(true));
                            si.DigestAlgorithm = pkcs7.GetDigestAlgorithm();
                            //si.EncryptionAlgorithm = pkcs7.GetEncryptionAlgorithm();
                            //si.FilterSubtype = pkcs7.GetFilterSubtype().Type;

                            //si.TimeStamp = pkcs7.TimeStampDate;
                            //si.TimeStampService = pkcs7.TimeStampToken.TimeStampInfo.Tsa.Name.;
                            //si.TimeStampVerified = pkcs7.VerifyTimestampImprint();

                            //verifica certificati
                            var errors =
                                iTextSharp.text.pdf.security.CertificateVerification.VerifyCertificates(
                                    pkcs7.SignCertificateChain, keyStore, pkcs7.SignDate);
                            if (errors.Count > 0)
                            {
                                si.ChainCertificatesNotValidAtSignedTime = true;
                            }

                            //foreach (var cert in pkcs7.SignCertificateChain)
                            //{
                            //    try
                            //    {
                            //        cert.CheckValidity(pkcs7.SignDate);
                            //    }
                            //    catch (Org.BouncyCastle.Security.Certificates.CertificateExpiredException ex1)
                            //    {
                            //        //si.ChainCertificatesExpiredAtSignedTime = true;
                            //    }
                            //    catch (Org.BouncyCastle.Security.Certificates.CertificateNotYetValidException ex2)
                            //    {
                            //        si.ChainCertificatesNotValidAtSignedTime = true;
                            //    }
                            //}

                            //verifica revocation
                            if (CheckRevocation)
                            {
                                try
                                {
                                    //si.CertificateRevocatedAtSignedTime = pkcs7.IsRevocationValid();
                                    List<Org.BouncyCastle.Ocsp.BasicOcspResp> ocsps =
                                        new List<Org.BouncyCastle.Ocsp.BasicOcspResp>();
                                    if (pkcs7.Ocsp != null)
                                        ocsps.Add(pkcs7.Ocsp);
                                    iTextSharp.text.pdf.security.OcspVerifier ocspVerifier = new OcspVerifier(null,
                                                                                                              ocsps);
                                    var issueCert =
                                        keyStore.SingleOrDefault(
                                            c => c.SubjectDN.Equals(pkcs7.SigningCertificate.IssuerDN));
                                    if (issueCert==null)
                                        throw new Exception("Issuer certificate not found.");
                                    List<VerificationOK> verification = ocspVerifier.Verify(
                                        pkcs7.SigningCertificate,
                                        issueCert,
                                        pkcs7.SignDate);
                                    if (verification.Count == 0)
                                    {
                                        var crls = new List<Org.BouncyCastle.X509.X509Crl>(pkcs7.CRLs);
                                        CrlVerifier crlVerifier = new CrlVerifier(null, crls);
                                        crlVerifier.OnlineCheckingAllowed = true;
                                        verification = crlVerifier.Verify(pkcs7.SigningCertificate, issueCert,
                                                                          pkcs7.SignDate);
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

                        }
                    }
                    reader.Close();
                }

                //result.SignaturesValid = result.SignatureInfos.All(si => si.IntegrityValid
                //                                         &&
                //                                         !si.ChainCertificatesNotValidAtSignedTime
                //                                         &&
                //                                         (!CheckRevocation || !si.CertificateRevocatedAtSignedTime
                //                                           .GetValueOrDefault(true)));

                //System.Diagnostics.Trace.WriteLine(string.Format("Verifica firme del file {0} completata con esito {1}", System.IO.Path.GetFileName(fileName),result.SignaturesValid?"Positivo":"Negativo"));

                return result;
            }
            catch (InvalidPdfException ex)
            {
                System.Diagnostics.Trace.WriteLine(string.Format("Si è verificato il seguente errore durante la verifica delle firme del file {0} {1}", System.IO.Path.GetFileName(fileName), ex.Message));
                throw ex;
            }
            catch (Exception exx)
            {
                System.Diagnostics.Trace.WriteLine(string.Format("Si è verificato il seguente errore durante la verifica delle firme del file {0} {1}", System.IO.Path.GetFileName(fileName), exx.Message));
                throw exx;
            }
        }

        
    }
}
