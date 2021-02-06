using System;
using Application.Controllers;
using Microsoft.AspNetCore.Mvc.Rendering;

namespace Application.Models.Web.Mvc.Rendering.Extensions
{
	public static class HtmlHelperExtension
	{
		#region Methods

		public static bool IsActive(this IHtmlHelper htmlHelper, string action = null, string controller = null)
		{
			if(htmlHelper == null)
				return false;

			action ??= nameof(HomeController.Index);
			controller ??= "Home";

			var activeAction = htmlHelper.ViewContext.RouteData.Values["Action"] as string;
			var activeController = htmlHelper.ViewContext.RouteData.Values["Controller"] as string;

			return string.Equals(action, activeAction, StringComparison.OrdinalIgnoreCase) && string.Equals(controller, activeController, StringComparison.OrdinalIgnoreCase);
		}

		#endregion
	}
}