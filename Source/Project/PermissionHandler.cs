using System;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;

namespace HansKindberg.Web.Authorization
{
	[CLSCompliant(false)]
	public class PermissionHandler : AuthorizationHandler<PermissionRequirement>
	{
		#region Constructors

		public PermissionHandler(IAuthorizationResolver authorizationResolver)
		{
			this.AuthorizationResolver = authorizationResolver ?? throw new ArgumentNullException(nameof(authorizationResolver));
		}

		#endregion

		#region Properties

		protected internal virtual IAuthorizationResolver AuthorizationResolver { get; }

		#endregion

		#region Methods

		protected override async Task HandleRequirementAsync(AuthorizationHandlerContext context, PermissionRequirement requirement)
		{
			if(context == null)
				throw new ArgumentNullException(nameof(context));

			if(requirement == null)
				throw new ArgumentNullException(nameof(requirement));

			if(await this.AuthorizationResolver.HasPermissionAsync(requirement.Name, context.User))
				context.Succeed(requirement);
		}

		#endregion
	}
}