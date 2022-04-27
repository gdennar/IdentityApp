using Microsoft.AspNetCore.Authorization.Infrastructure;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using IdentityApp.Models;



namespace IdentityApp.Authorization
{
        public class InvoiceAdminAuthorizationHandler :
            AuthorizationHandler<OperationAuthorizationRequirement, Invoice>
        {

            protected override Task HandleRequirementAsync(
                AuthorizationHandlerContext context,
                OperationAuthorizationRequirement requirement,
                Invoice invoice)
            {
                if (context.User == null || invoice == null)
                    return Task.CompletedTask;
                


                if (context.User.IsInRole(Constants.AdministratorRole))
                    context.Succeed(requirement);

                return Task.CompletedTask;

            }
        }
    }



