using Microsoft.AspNetCore.DataProtection.KeyManagement;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography;
using System.Text.Json.Nodes;
using System.Text;

namespace AlipayPlayground.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class PayController : ControllerBase
    {
        public readonly string CertLocation = "C:\\Users\\jiann\\source\\repos\\AlipayPlayground\\AlipayPlayground\\SelfSignCert\\";
        [Route("Health")]
        [HttpGet]
        public string Health()
        {
            var strRequestBody = "{\"order\":{\"orderId\":\"OrderID_0101010101\",\"orderDescription\":\"sample_order\",\"orderAmount\":{\"value\":\"100\",\"currency\":\"JPY\"}},\"paymentAmount\":{\"value\":\"100\",\"currency\":\"JPY\"},\"paymentFactor\":{\"isInStorePayment\":\"true\"}}";

            var requestUri = "/aps/api/v1/payments/pay";
            var clientId = "TEST_5X00000000000000";
            var requestTime = DateTime.Parse("2019-05-28T12:12:12+08:00");
            var requestBody = JsonObject.Parse(strRequestBody);

            var contentToBeSign = $"POST {requestUri}\r\n{clientId}.{requestTime.ToLocalTime().ToString("yyyy-MM-ddTHH:mm:sszzz")}.{requestBody}";

            var signature = SignData(ConvertStringToByte(contentToBeSign), CertLocation + "jiann.pfx", "Password1");

            var verify = VerifySignature(ConvertStringToByte(contentToBeSign), signature, CertLocation + "jiann.crt");


            return "Healty";
        }

        public static string SignData(byte[] data, string pkcs12File, string pkcs12Password)
        {
            X509Certificate2 signerCert = new X509Certificate2(pkcs12File, pkcs12Password, X509KeyStorageFlags.Exportable);            
            RSACryptoServiceProvider rsaCSP = new RSACryptoServiceProvider();
            rsaCSP.FromXmlString(signerCert.PrivateKey.ToXmlString(true));
            var SignedData = rsaCSP.SignData(data, CryptoConfig.MapNameToOID("SHA256"));
            return Convert.ToBase64String(SignedData);
        }

        public static bool VerifySignature(byte[] data, string signature, string publicCert)
        {
            X509Certificate2 partnerCert = new X509Certificate2(publicCert);
            using (RSACng rsaCng = (RSACng)partnerCert.GetRSAPublicKey())
            {
                return rsaCng.VerifyData(data, Convert.FromBase64String(signature), HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            }
        }

        public static byte[] ConvertStringToByte(string str)
        {
            return  Encoding.ASCII.GetBytes(str);
        }
    }
}

