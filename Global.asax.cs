using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.Http;
using System.Web.Mvc;
using System.Web.Optimization;
using System.Web.Routing;
using System.Xml;

namespace MetLife.Annuities.Web
{
    // Note: For instructions on enabling IIS6 or IIS7 classic mode, 
    // visit http://go.microsoft.com/?LinkId=9394801

    public class MvcApplication : System.Web.HttpApplication
    {
        protected void Application_Start()
        {
            AreaRegistration.RegisterAllAreas();
            WebApiConfig.Register(GlobalConfiguration.Configuration);
            FilterConfig.RegisterGlobalFilters(GlobalFilters.Filters);
            RouteConfig.RegisterRoutes(RouteTable.Routes);
            BundleTable.EnableOptimizations = true;
            BundleConfig.RegisterBundles(BundleTable.Bundles);
            AuthConfig.RegisterAuth();

        }

        protected void Application_Error(object sender, EventArgs e)
        {
            Exception ex = Server.GetLastError();
            if (ex is MetLife.Annuities.Services.Email.DNSSException)
                HttpContext.Current.Response.StatusCode = 520;
            else
            {
                // TBD - calculate the error code based on exception type.
                string id = Encryption.Encrypt("E001");
                Response.Redirect("~/public/pages/CustomError.html?id="+id);
            }
                //HttpContext.Current.Response.StatusCode = 500;

            
            //HttpContext.Current.Response.

            // get the message from xml file based on Message ID
            //XmlDocument xmldoc = new XmlDocument();
            //string filepath = string.Empty;
            //XmlNode node = null;
            //string message = string.Empty;
            //filepath = System.Web.HttpContext.Current.Server.MapPath("MailInfo.xml");

            //xmldoc.Load(filepath);

            //node = xmldoc.SelectSingleNode("messages/error[@id='" + 0 + "']");

            //if (node != null)
            //{
            //    message = node.SelectSingleNode("message").InnerText.Trim();

            //}

            //HttpContext.Current.Response.TrySkipIisCustomErrors = true;
        }
    }
}