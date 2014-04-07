using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.UI;
using System.Web.UI.WebControls;
using System.Web.Services;

namespace MetLife.Annuities.Web
{
    public partial class Encryption1 : System.Web.UI.Page
    {
        protected void Page_Load(object sender, EventArgs e)
        {

        }

        public string Encrypt(string data)
        {
            return Encryption.Encrypt(data);
        }

        [WebMethod]
        [System.Web.Script.Services.ScriptMethod]
        public static string Decrypt(string encryptedData)
        {
            return Encryption.Decrypt(encryptedData);
        }

    }
}