using PointOfSale.Models;
using System;
using System.Linq;
using System.Web.Mvc;
using System.Web.Routing;

namespace PointOfSale.Helper
{
    public class AuthorizationFilter : AuthorizeAttribute, IAuthorizationFilter
    {
        public void OnAuthorization(AuthorizationContext filterContext)
        {
            POS_ProjectEntities db = new POS_ProjectEntities();
            string username = Convert.ToString(System.Web.HttpContext.Current.Session["Username"]);
            string role = Convert.ToString(System.Web.HttpContext.Current.Session["Role"]);
            string actionName = filterContext.ActionDescriptor.ActionName;
            string controllerName = filterContext.ActionDescriptor.ControllerDescriptor.ControllerName;
            string tag = controllerName + actionName;

            if (filterContext.ActionDescriptor.IsDefined(typeof(AllowAnonymousAttribute), true)
                || filterContext.ActionDescriptor.ControllerDescriptor.IsDefined(typeof(AllowAnonymousAttribute), true))
            {
                // Don't check for authorization as AllowAnonymous filter is applied to the action or controller
                return;
            }

            // Check for authorization
            if (System.Web.HttpContext.Current.Session["Username"] == null)
            {
                filterContext.Result = new HttpUnauthorizedResult();
            }
            if (username != null && username != "")
            {
                bool isPermitted = false;

                var viewPermission = db.RolePermissions.Where(x => x.Role.ToLower() == role.ToLower() && x.Tag.ToLower() == tag.ToLower()).SingleOrDefault();
                if (viewPermission != null)
                {
                    isPermitted = true;
                }
                if (isPermitted == false)
                {
                    filterContext.Result = new RedirectToRouteResult(
                      new RouteValueDictionary  
                        {  
                             { "controller", "Home" },  
                             { "action", "AccessDenied" }
                        });
                }
            }
        }
    }
}