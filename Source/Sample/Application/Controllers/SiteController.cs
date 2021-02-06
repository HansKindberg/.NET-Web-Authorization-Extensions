using System;
using Application.Models;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using RegionOrebroLan.Logging.Extensions;

namespace Application.Controllers
{
	public abstract class SiteController : Controller
	{
		#region Constructors

		protected SiteController(IFacade facade)
		{
			this.Facade = facade ?? throw new ArgumentNullException(nameof(facade));
			this.Logger = (facade.LoggerFactory ?? throw new ArgumentException("The logger-factory property can not be null.", nameof(facade))).CreateLogger(this.GetType());
		}

		#endregion

		#region Properties

		protected internal virtual IFacade Facade { get; }
		protected internal virtual ILogger Logger { get; }

		#endregion

		#region Methods

		protected internal virtual string ResolveAndValidateReturnUrl(string returnUrl)
		{
			returnUrl = this.ResolveReturnUrl(returnUrl);

			// ReSharper disable InvertIf
			if(!this.Url.IsLocalUrl(returnUrl))
			{
				var message = $"The return-url \"{returnUrl}\" is invalid";

				this.Logger.LogErrorIfEnabled(message);

				throw new InvalidOperationException(message);
			}
			// ReSharper restore InvertIf

			return returnUrl;
		}

		protected internal virtual string ResolveReturnUrl(string returnUrl)
		{
			return string.IsNullOrEmpty(returnUrl) ? "~/" : returnUrl;
		}

		#endregion
	}
}