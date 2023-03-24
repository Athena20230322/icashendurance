using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Web;
using ICP.KeyExchange.TestLibrary.Helpers;
using ICP.KeyExchange.TestLibrary.Models;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;


namespace ICP.KeyExchange.TestLibrary.Test


{
    [TestClass]
    public class CertificateApiTest
    {
        int i = 0;
        string enc;
        private readonly HttpClient _httpClient = new HttpClient
        {
            //BaseAddress = new Uri("http://localhost:3311")
          //  BaseAddress = new Uri("http://icp-member-beta.ecpay.com.tw/")
              BaseAddress = new Uri("https://icp-member-stage.icashpay.com.tw/")
            // BaseAddress = new Uri("https://icp-member-beta.opay.tw/")


           
        };
        private readonly RsaCryptoHelper _rsaCryptoHelper = new RsaCryptoHelper();
        private readonly AesCryptoHelper _aesCryptoHelper = new AesCryptoHelper();

        private string _serverPublicKey = null;
        private string _clientPublicKey = null;
        private string _clientPrivateKey = null;
        private long _aesClientCertId = -1;
        private string _aesKey = null;
        private string _aesIv = null;

        [TestMethod]
        public void GetDefaultPucCert()
        {
            getDefaultPucCert();
        }

        [TestMethod]
        public void ExchangePucCert()
        {
            exchangePucCert();
        }

        [TestMethod]
        public void GenerateAES()
        {
            generateAES();
        }

        private (string Content, string Signature) callCertificateApi(string action, long certId, string serverPublicKey, string clientPrivateKey, object obj, string certHeaderName)
        {
            string json = JsonConvert.SerializeObject(obj);

            _rsaCryptoHelper.ImportPemPublicKey(serverPublicKey);
            string encData = _rsaCryptoHelper.Encrypt(json);

            _rsaCryptoHelper.ImportPemPrivateKey(clientPrivateKey);
            Console.WriteLine("CP1");
            Console.WriteLine(clientPrivateKey);


            string signature = _rsaCryptoHelper.SignDataWithSha256(encData);
            Console.WriteLine("CP2");
            Console.WriteLine(signature);

            Console.WriteLine("CP3");
            Console.WriteLine(encData);
            IDictionary<string, string> form = new Dictionary<string, string>();
            form.Add("EncData", encData);

            var content = new FormUrlEncodedContent(form);
            content.Headers.Add(certHeaderName, certId.ToString());
            content.Headers.Add("X-iCP-Signature", signature);
            //Console.WriteLine("X-iCP-S0");
            //Console.WriteLine(signature);

            var postResult = _httpClient.PostAsync(action, content).Result;
            string stringResult = postResult.Content.ReadAsStringAsync().Result;



            Console.WriteLine("post1");
            Console.WriteLine(postResult);


            var headerSignature = postResult.Headers.Where(x => x.Key == "X-iCP-Signature").FirstOrDefault();


            string resultSignature = headerSignature.Value?.FirstOrDefault();

            //Console.WriteLine("X-iCP-S1");
            //Console.WriteLine(resultSignature);

            //Console.WriteLine("X-iCP-S1-1");
            //Console.WriteLine(stringResult);
            return (stringResult, resultSignature);



        }

        private void checkTimestamp(string timestamp)
        {
            if (!DateTime.TryParse(timestamp, out DateTime dt))
            {
                throw new Exception("Timestamp 有誤");
            }

            double subSec = DateTime.Now.Subtract(dt).TotalSeconds;
            if (subSec > 30 || subSec < -30)
            {
                throw new Exception("Timestamp 誤差過大");
            }
        }

        private (long CertId, string PublicKey) getDefaultPucCert()
        {
            string url = "/api/member/Certificate/GetDefaultPucCert";

            var postResult = _httpClient.PostAsync(url, null).Result;
            string stringResult = postResult.Content.ReadAsStringAsync().Result;

            Console.WriteLine($"回傳：{stringResult}");

            JObject jObj = JObject.Parse(stringResult);
            int rtnCode = jObj.Value<int>("RtnCode");
            Assert.AreEqual(1, rtnCode);

            long certId = jObj.Value<long>("DefaultPubCertID");
            string publicKey = jObj.Value<string>("DefaultPubCert");

            return (certId, publicKey);
        }

        private (ExchangePucCertResult Result, string ClientPrivateKey) exchangePucCert()
        {
            var getDefaultPucCertResult = getDefaultPucCert();

            var key = _rsaCryptoHelper.GeneratePemKey();
            var result = callCertificateApi("/api/member/Certificate/ExchangePucCert",
                                 getDefaultPucCertResult.CertId,
                                 getDefaultPucCertResult.PublicKey,


                                 key.PrivateKey,
                                 new ExchangePucCertRequest
                                 {
                                     ClientPubCert = key.PublicKey,
                                     Timestamp = DateTime.Now.ToString("yyyy/MM/dd HH:mm:ss")
                                 },
                                 "X-iCP-DefaultPubCertID");


            Console.WriteLine("PUBC");
            Console.WriteLine(key.PublicKey);



            var apiResult = JsonConvert.DeserializeObject<AuthorizationApiEncryptResult>(result.Content);
            if (apiResult.RtnCode != 1)
            {
                throw new Exception(apiResult.RtnMsg);
            }

            _rsaCryptoHelper.ImportPemPrivateKey(key.PrivateKey);
            string json = _rsaCryptoHelper.Decrypt(apiResult.EncData);

            var exchangePucCertResult = JsonConvert.DeserializeObject<ExchangePucCertResult>(json);

            _rsaCryptoHelper.ImportPemPublicKey(exchangePucCertResult.ServerPubCert);
            bool isValid = _rsaCryptoHelper.VerifySignDataWithSha256(result.Content, result.Signature);
            if (!isValid)
            {
                throw new Exception("簽章驗證失敗");
            }

            checkTimestamp(exchangePucCertResult.Timestamp);

            _clientPrivateKey = key.PrivateKey;
            _clientPublicKey = key.PublicKey;
            _serverPublicKey = exchangePucCertResult.ServerPubCert;

            Console.WriteLine("PUBC1");
            Console.WriteLine(json);

            return (exchangePucCertResult, key.PrivateKey);
        }




        private void generateAES()
        {
            var exchangePucCertResult = exchangePucCert();
            var result = callCertificateApi("/api/member/Certificate/GenerateAES",
                                 exchangePucCertResult.Result.ServerPubCertID,
                                 exchangePucCertResult.Result.ServerPubCert,
                                 exchangePucCertResult.ClientPrivateKey,



            new BaseAuthorizationApiRequest
            {
                Timestamp = DateTime.Now.ToString("yyyy/MM/dd HH:mm:ss")
            },
                                 "X-iCP-ServerPubCertID");

            Console.WriteLine("aescp");
            Console.WriteLine(exchangePucCertResult.ClientPrivateKey);

            var apiResult = JsonConvert.DeserializeObject<AuthorizationApiEncryptResult>(result.Content);
            if (apiResult.RtnCode != 1)
            {
                throw new Exception(apiResult.RtnMsg);
            }

            _rsaCryptoHelper.ImportPemPrivateKey(exchangePucCertResult.ClientPrivateKey);
            string json = _rsaCryptoHelper.Decrypt(apiResult.EncData);
            if (i == 1)
            {

                using (StreamWriter writer = new StreamWriter("keyiv1.txt"))


                {
                    // writer.WriteLine("");

                    writer.WriteLine(json);

                }


            }
           

            var generateAesResult = JsonConvert.DeserializeObject<GenerateAesResult>(json);

            _rsaCryptoHelper.ImportPemPublicKey(exchangePucCertResult.Result.ServerPubCert);
            bool isValid = _rsaCryptoHelper.VerifySignDataWithSha256(result.Content, result.Signature);

            //Console.WriteLine("isV");
            //Console.WriteLine(isValid);
            if (!isValid)
            {
                throw new Exception("簽章驗證失敗");
            }
            Console.WriteLine("aespubk");
            Console.WriteLine(_clientPublicKey);

            Console.WriteLine("=======================================");
            Console.WriteLine(_serverPublicKey);


            checkTimestamp(generateAesResult.Timestamp);

            _aesClientCertId = generateAesResult.EncKeyID;
            _aesKey = generateAesResult.AES_Key;
            _aesIv = generateAesResult.AES_IV;
        }

        private string callNormalApi(string url, object obj, ref string decryptContent)
        {

            string json = JsonConvert.SerializeObject(obj);

            _aesCryptoHelper.Key = _aesKey;
            _aesCryptoHelper.Iv = _aesIv;
            string encData = _aesCryptoHelper.Encrypt(json);

            _rsaCryptoHelper.ImportPemPrivateKey(_clientPrivateKey);
            //Console.WriteLine("555555===================================================");
            //Console.WriteLine(_clientPrivateKey);
            string signature = _rsaCryptoHelper.SignDataWithSha256(encData);
            //Console.WriteLine("fouth result==============================================");
            //Console.WriteLine(signature);
            IDictionary<string, string> form = new Dictionary<string, string>();
            form.Add("EncData", encData);
            // enc = enc+encData+',';

            //    using (StreamWriter writer = new StreamWriter("enc111.txt"))


            //   {
            ////        // writer.WriteLine("");

            //        writer.WriteLine(encData);

            //    }

            if (i == 1)
            {

                using (StreamWriter writer = new StreamWriter("enc1.txt"))



                {
                    writer.WriteLine("");

                    writer.WriteLine(encData);
                    //StreamReader sr = new StreamReader("all.txt");
                    //string line;
                    //while ((line = sr.ReadLine()) != null)
                    //{

                    //    Console.WriteLine(line.ToString());



                    //}


                    Console.WriteLine("Test1111");
                }


            }
            //else if (i == 2)
            //{

            //    using (StreamWriter writer = new StreamWriter("enc2.txt"))


            //    {
            //        // writer.WriteLine("");

            //        writer.WriteLine(encData);

            //    }

            //}

           




            var content = new FormUrlEncodedContent(form);
            content.Headers.Add("X-iCP-EncKeyID", _aesClientCertId.ToString());
            content.Headers.Add("X-iCP-Signature", signature);

            string s = _aesClientCertId.ToString();
            string a = signature;
            var postResult = _httpClient.PostAsync(url, content).Result;
            string stringResult = postResult.Content.ReadAsStringAsync().Result;
           

         

            if (i == 1)
            {

                using (StreamWriter writer = new StreamWriter("post1-1.txt"))
                   


                {
                    //writer.WriteLine("");

                    //  writer.WriteLine(content.Headers);

                    writer.WriteLine(s);

                }

                using (StreamWriter writer = new StreamWriter("post1-2.txt"))


                {
                    //writer.WriteLine("");

                    // writer.WriteLine(content.Headers);

                    writer.WriteLine(a);

                }

            }
           

            var headerSignature = postResult.Headers.Where(x => x.Key == "X-iCP-Signature").FirstOrDefault();


            string resultSignature = headerSignature.Value?.FirstOrDefault();
            //Console.WriteLine("X-iCP-S3");
            //Console.WriteLine(resultSignature);

            _rsaCryptoHelper.ImportPemPublicKey(_serverPublicKey);
            bool isValid = _rsaCryptoHelper.VerifySignDataWithSha256(stringResult, resultSignature);
            if (!isValid)
            {
                throw new Exception("簽章驗證失敗");
            }

            JToken jToken = JToken.Parse(stringResult);
            if (jToken["RtnCode"].Value<int>() != 1)
            {
                throw new Exception(jToken["RtnMsg"].Value<string>());
            }

            decryptContent = _aesCryptoHelper.Decrypt(jToken["EncData"].Value<string>());
            var jObj = JObject.Parse(decryptContent);
            string Timestamp = jObj.Value<string>("Timestamp");
            checkTimestamp(Timestamp);
            return stringResult;
        }

        [TestMethod]


        public void GetCellphone()
        {
            for (i = 1; i <= 1; i++)
            {
                generateAES();
                //string url = "/api/member/MemberInfo/getCellphone";
                 string url = "/app/MemberInfo/UserCodeLogin2022";
                // string url = "/app/Member/MemberInfo/SetRegisterInfo2022";
                //string url = "/app/MemberInfo/SendAuthSMS";
                //string url = "/app/MemberInfo/RefreshLoginToken";
                // string url = "/api/Member/MemberInfo/CheckRegisterAuthSMS";

                // string url = "/api/Member/Payment/CreateBarcode";
                // string url = "/app/MemberInfo/RefreshLoginToken";

                //string url ="/app/certificate/bindMerchantCert";


                if (i == 1)


                { 
              

                    var request1 = new
                    {
                       // Timestamp = DateTime.Now.ToString("2023/03/07 10:30:00"),
                        Timestamp = DateTime.Now.ToString("yyyy/MM/dd HH:mm:ss"),
                        //  MerchantID = "10000290",
                        //  Token = "6EBD151DA3D64905A7651FA90B439DFB",
                        // PaymentType = "1" ,
                        // PayID ="1"
                         LoginType = "1",
                        //LoginTokenID = "6690DF0626F0415A8F48F4D7940C4EFB,24906",

                        //  AuthV = "62DEEED78C9F448080DB4307AF6CF4A1",

                        // AuthV = "20888234523452F54235423B54235545",
                        //  AuthV = "69D1076AD6E948ECAE7678DE156756D6",

                        //CellPhone = "0912334460",
                        SMSAuthCode = "114775",
                        UserCode = "icp00909",
                        UserPwd = "Aa123456"
                        // SMSAuthType = "5"
                    };
                    string decryptContent1 = null;
                    string response1 = callNormalApi(url, request1, ref decryptContent1);
                    //string test = _rsaCryptoHelper.Decrypt(response);
                    //Console.WriteLine(test);

                    using (StreamWriter writer = new StreamWriter("UserCodeLogin2022.txt"))
                    {
                        writer.WriteLine(response1);

                        //     //   writer.WriteLine(test);
                    }



                        }


                //Console.WriteLine("second result==================================================");
                //Console.WriteLine(response);



                //if (i == 2)


                //{

                //    var request1 = new
                //    {
                //        Timestamp = DateTime.Now.ToString("yyyy/MM/dd HH:mm:ss"),
                //         LoginTokenID = "98BE5F7839D04BF28C0B2EC753348DE0",
                //       // AuthV = "115C5234523452F54235423B54235545"
                //        // CellPhone = "0916092609",
                //        //AuthCode = "806099"
                //        UserCode = "johnny002",
                //        UserPwd = "Aa1234"
                //        //SMSAuthType = "1"
                //    };
                //    string decryptContent1 = null;
                //    string response1 = callNormalApi(url, request1, ref decryptContent1);
                //    using (StreamWriter writer = new StreamWriter("important2.txt"))
                //    {
                //        writer.WriteLine(response1);
                     

                //    }
                //}


















            }


        }


        }




    }

