#pragma checksum "C:\Users\ELNUR\Desktop\Backend Home\Visual Studio\Pronia\Pronia\Areas\Manage\Views\Product\Index.cshtml" "{ff1816ec-aa5e-4d10-87f7-6f4963833460}" "33c1d7bd286af87ad4aa38b6ae6e7502511cf316"
// <auto-generated/>
#pragma warning disable 1591
[assembly: global::Microsoft.AspNetCore.Razor.Hosting.RazorCompiledItemAttribute(typeof(AspNetCore.Areas_Manage_Views_Product_Index), @"mvc.1.0.view", @"/Areas/Manage/Views/Product/Index.cshtml")]
namespace AspNetCore
{
    #line hidden
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Threading.Tasks;
    using Microsoft.AspNetCore.Mvc;
    using Microsoft.AspNetCore.Mvc.Rendering;
    using Microsoft.AspNetCore.Mvc.ViewFeatures;
#nullable restore
#line 1 "C:\Users\ELNUR\Desktop\Backend Home\Visual Studio\Pronia\Pronia\Areas\Manage\Views\_ViewImports.cshtml"
using Pronia;

#line default
#line hidden
#nullable disable
#nullable restore
#line 2 "C:\Users\ELNUR\Desktop\Backend Home\Visual Studio\Pronia\Pronia\Areas\Manage\Views\_ViewImports.cshtml"
using Pronia.Models;

#line default
#line hidden
#nullable disable
    [global::Microsoft.AspNetCore.Razor.Hosting.RazorSourceChecksumAttribute(@"SHA1", @"33c1d7bd286af87ad4aa38b6ae6e7502511cf316", @"/Areas/Manage/Views/Product/Index.cshtml")]
    [global::Microsoft.AspNetCore.Razor.Hosting.RazorSourceChecksumAttribute(@"SHA1", @"468c94be3b2f4c2f145e67bc5cb11372be49a7b1", @"/Areas/Manage/Views/_ViewImports.cshtml")]
    #nullable restore
    public class Areas_Manage_Views_Product_Index : global::Microsoft.AspNetCore.Mvc.Razor.RazorPage<List<Product>>
    #nullable disable
    {
        private static readonly global::Microsoft.AspNetCore.Razor.TagHelpers.TagHelperAttribute __tagHelperAttribute_0 = new global::Microsoft.AspNetCore.Razor.TagHelpers.TagHelperAttribute("method", "post", global::Microsoft.AspNetCore.Razor.TagHelpers.HtmlAttributeValueStyle.DoubleQuotes);
        private static readonly global::Microsoft.AspNetCore.Razor.TagHelpers.TagHelperAttribute __tagHelperAttribute_1 = new global::Microsoft.AspNetCore.Razor.TagHelpers.TagHelperAttribute("asp-action", "SoftDelete", global::Microsoft.AspNetCore.Razor.TagHelpers.HtmlAttributeValueStyle.DoubleQuotes);
        private static readonly global::Microsoft.AspNetCore.Razor.TagHelpers.TagHelperAttribute __tagHelperAttribute_2 = new global::Microsoft.AspNetCore.Razor.TagHelpers.TagHelperAttribute("asp-action", "HardDelete", global::Microsoft.AspNetCore.Razor.TagHelpers.HtmlAttributeValueStyle.DoubleQuotes);
        private static readonly global::Microsoft.AspNetCore.Razor.TagHelpers.TagHelperAttribute __tagHelperAttribute_3 = new global::Microsoft.AspNetCore.Razor.TagHelpers.TagHelperAttribute("asp-action", "Active", global::Microsoft.AspNetCore.Razor.TagHelpers.HtmlAttributeValueStyle.DoubleQuotes);
        private static readonly global::Microsoft.AspNetCore.Razor.TagHelpers.TagHelperAttribute __tagHelperAttribute_4 = new global::Microsoft.AspNetCore.Razor.TagHelpers.TagHelperAttribute("style", new global::Microsoft.AspNetCore.Html.HtmlString("height:100%"), global::Microsoft.AspNetCore.Razor.TagHelpers.HtmlAttributeValueStyle.DoubleQuotes);
        private static readonly global::Microsoft.AspNetCore.Razor.TagHelpers.TagHelperAttribute __tagHelperAttribute_5 = new global::Microsoft.AspNetCore.Razor.TagHelpers.TagHelperAttribute("alt", new global::Microsoft.AspNetCore.Html.HtmlString("Alternate Text"), global::Microsoft.AspNetCore.Razor.TagHelpers.HtmlAttributeValueStyle.DoubleQuotes);
        private static readonly global::Microsoft.AspNetCore.Razor.TagHelpers.TagHelperAttribute __tagHelperAttribute_6 = new global::Microsoft.AspNetCore.Razor.TagHelpers.TagHelperAttribute("asp-action", "Edit", global::Microsoft.AspNetCore.Razor.TagHelpers.HtmlAttributeValueStyle.DoubleQuotes);
        private static readonly global::Microsoft.AspNetCore.Razor.TagHelpers.TagHelperAttribute __tagHelperAttribute_7 = new global::Microsoft.AspNetCore.Razor.TagHelpers.TagHelperAttribute("class", new global::Microsoft.AspNetCore.Html.HtmlString("btn btn-outline-primary mx-lg-1"), global::Microsoft.AspNetCore.Razor.TagHelpers.HtmlAttributeValueStyle.DoubleQuotes);
        #line hidden
        #pragma warning disable 0649
        private global::Microsoft.AspNetCore.Razor.Runtime.TagHelpers.TagHelperExecutionContext __tagHelperExecutionContext;
        #pragma warning restore 0649
        private global::Microsoft.AspNetCore.Razor.Runtime.TagHelpers.TagHelperRunner __tagHelperRunner = new global::Microsoft.AspNetCore.Razor.Runtime.TagHelpers.TagHelperRunner();
        #pragma warning disable 0169
        private string __tagHelperStringValueBuffer;
        #pragma warning restore 0169
        private global::Microsoft.AspNetCore.Razor.Runtime.TagHelpers.TagHelperScopeManager __backed__tagHelperScopeManager = null;
        private global::Microsoft.AspNetCore.Razor.Runtime.TagHelpers.TagHelperScopeManager __tagHelperScopeManager
        {
            get
            {
                if (__backed__tagHelperScopeManager == null)
                {
                    __backed__tagHelperScopeManager = new global::Microsoft.AspNetCore.Razor.Runtime.TagHelpers.TagHelperScopeManager(StartTagHelperWritingScope, EndTagHelperWritingScope);
                }
                return __backed__tagHelperScopeManager;
            }
        }
        private global::Microsoft.AspNetCore.Mvc.TagHelpers.FormTagHelper __Microsoft_AspNetCore_Mvc_TagHelpers_FormTagHelper;
        private global::Microsoft.AspNetCore.Mvc.TagHelpers.RenderAtEndOfFormTagHelper __Microsoft_AspNetCore_Mvc_TagHelpers_RenderAtEndOfFormTagHelper;
        private global::Microsoft.AspNetCore.Mvc.Razor.TagHelpers.UrlResolutionTagHelper __Microsoft_AspNetCore_Mvc_Razor_TagHelpers_UrlResolutionTagHelper;
        private global::Microsoft.AspNetCore.Mvc.TagHelpers.AnchorTagHelper __Microsoft_AspNetCore_Mvc_TagHelpers_AnchorTagHelper;
        #pragma warning disable 1998
        public async override global::System.Threading.Tasks.Task ExecuteAsync()
        {
#nullable restore
#line 2 "C:\Users\ELNUR\Desktop\Backend Home\Visual Studio\Pronia\Pronia\Areas\Manage\Views\Product\Index.cshtml"
  
    ViewData["Title"] = "Products";

#line default
#line hidden
#nullable disable
            WriteLiteral(@"<!-- Modal -->
<div class=""modal fade"" id=""deleteModal"" tabindex=""-1"" role=""dialog"" aria-labelledby=""exampleModalLabel"" aria-hidden=""true"">
    <div class=""modal-dialog"" role=""document"">
        <div class=""modal-content"">
            <div class=""modal-body"">
                Are you want to delete?
            </div>
            <div class=""modal-footer"">
                ");
            __tagHelperExecutionContext = __tagHelperScopeManager.Begin("form", global::Microsoft.AspNetCore.Razor.TagHelpers.TagMode.StartTagAndEndTag, "33c1d7bd286af87ad4aa38b6ae6e7502511cf3166899", async() => {
                WriteLiteral("\r\n                    <button type=\"submit\" class=\"btn btn-primary\">Yes</button>\r\n                    <button type=\"button\" class=\"btn btn-secondary\" data-dismiss=\"modal\">No</button>\r\n                ");
            }
            );
            __Microsoft_AspNetCore_Mvc_TagHelpers_FormTagHelper = CreateTagHelper<global::Microsoft.AspNetCore.Mvc.TagHelpers.FormTagHelper>();
            __tagHelperExecutionContext.Add(__Microsoft_AspNetCore_Mvc_TagHelpers_FormTagHelper);
            __Microsoft_AspNetCore_Mvc_TagHelpers_RenderAtEndOfFormTagHelper = CreateTagHelper<global::Microsoft.AspNetCore.Mvc.TagHelpers.RenderAtEndOfFormTagHelper>();
            __tagHelperExecutionContext.Add(__Microsoft_AspNetCore_Mvc_TagHelpers_RenderAtEndOfFormTagHelper);
            __Microsoft_AspNetCore_Mvc_TagHelpers_FormTagHelper.Method = (string)__tagHelperAttribute_0.Value;
            __tagHelperExecutionContext.AddTagHelperAttribute(__tagHelperAttribute_0);
            __Microsoft_AspNetCore_Mvc_TagHelpers_FormTagHelper.Action = (string)__tagHelperAttribute_1.Value;
            __tagHelperExecutionContext.AddTagHelperAttribute(__tagHelperAttribute_1);
            await __tagHelperRunner.RunAsync(__tagHelperExecutionContext);
            if (!__tagHelperExecutionContext.Output.IsContentModified)
            {
                await __tagHelperExecutionContext.SetOutputContentAsync();
            }
            Write(__tagHelperExecutionContext.Output);
            __tagHelperExecutionContext = __tagHelperScopeManager.End();
            WriteLiteral(@"
            </div>
        </div>
    </div>
</div>

<!-- Modal -->
<div class=""modal fade"" id=""HarddeleteModal"" tabindex=""-1"" role=""dialog"" aria-labelledby=""exampleModalLabel"" aria-hidden=""true"">
    <div class=""modal-dialog"" role=""document"">
        <div class=""modal-content"">
            <div class=""modal-body"">
                Are you want to delete?
            </div>
            <div class=""modal-footer"">
                ");
            __tagHelperExecutionContext = __tagHelperScopeManager.Begin("form", global::Microsoft.AspNetCore.Razor.TagHelpers.TagMode.StartTagAndEndTag, "33c1d7bd286af87ad4aa38b6ae6e7502511cf3169207", async() => {
                WriteLiteral("\r\n                    <button type=\"submit\" class=\"btn btn-primary\">Yes</button>\r\n                    <button type=\"button\" class=\"btn btn-secondary\" data-dismiss=\"modal\">No</button>\r\n                ");
            }
            );
            __Microsoft_AspNetCore_Mvc_TagHelpers_FormTagHelper = CreateTagHelper<global::Microsoft.AspNetCore.Mvc.TagHelpers.FormTagHelper>();
            __tagHelperExecutionContext.Add(__Microsoft_AspNetCore_Mvc_TagHelpers_FormTagHelper);
            __Microsoft_AspNetCore_Mvc_TagHelpers_RenderAtEndOfFormTagHelper = CreateTagHelper<global::Microsoft.AspNetCore.Mvc.TagHelpers.RenderAtEndOfFormTagHelper>();
            __tagHelperExecutionContext.Add(__Microsoft_AspNetCore_Mvc_TagHelpers_RenderAtEndOfFormTagHelper);
            __Microsoft_AspNetCore_Mvc_TagHelpers_FormTagHelper.Method = (string)__tagHelperAttribute_0.Value;
            __tagHelperExecutionContext.AddTagHelperAttribute(__tagHelperAttribute_0);
            __Microsoft_AspNetCore_Mvc_TagHelpers_FormTagHelper.Action = (string)__tagHelperAttribute_2.Value;
            __tagHelperExecutionContext.AddTagHelperAttribute(__tagHelperAttribute_2);
            await __tagHelperRunner.RunAsync(__tagHelperExecutionContext);
            if (!__tagHelperExecutionContext.Output.IsContentModified)
            {
                await __tagHelperExecutionContext.SetOutputContentAsync();
            }
            Write(__tagHelperExecutionContext.Output);
            __tagHelperExecutionContext = __tagHelperScopeManager.End();
            WriteLiteral(@"
            </div>
        </div>
    </div>
</div>

<div class=""modal fade"" id=""ActiveModal"" tabindex=""-1"" role=""dialog"" aria-labelledby=""exampleModalLabel"" aria-hidden=""true"">
    <div class=""modal-dialog"" role=""document"">
        <div class=""modal-content"">
            <div class=""modal-body"">
                Are you want to active?
            </div>
            <div class=""modal-footer"">
                ");
            __tagHelperExecutionContext = __tagHelperScopeManager.Begin("form", global::Microsoft.AspNetCore.Razor.TagHelpers.TagMode.StartTagAndEndTag, "33c1d7bd286af87ad4aa38b6ae6e7502511cf31611495", async() => {
                WriteLiteral("\r\n                    <button type=\"submit\" class=\"btn btn-primary\">Yes</button>\r\n                    <button type=\"button\" class=\"btn btn-secondary\" data-dismiss=\"modal\">No</button>\r\n                ");
            }
            );
            __Microsoft_AspNetCore_Mvc_TagHelpers_FormTagHelper = CreateTagHelper<global::Microsoft.AspNetCore.Mvc.TagHelpers.FormTagHelper>();
            __tagHelperExecutionContext.Add(__Microsoft_AspNetCore_Mvc_TagHelpers_FormTagHelper);
            __Microsoft_AspNetCore_Mvc_TagHelpers_RenderAtEndOfFormTagHelper = CreateTagHelper<global::Microsoft.AspNetCore.Mvc.TagHelpers.RenderAtEndOfFormTagHelper>();
            __tagHelperExecutionContext.Add(__Microsoft_AspNetCore_Mvc_TagHelpers_RenderAtEndOfFormTagHelper);
            __Microsoft_AspNetCore_Mvc_TagHelpers_FormTagHelper.Method = (string)__tagHelperAttribute_0.Value;
            __tagHelperExecutionContext.AddTagHelperAttribute(__tagHelperAttribute_0);
            __Microsoft_AspNetCore_Mvc_TagHelpers_FormTagHelper.Action = (string)__tagHelperAttribute_3.Value;
            __tagHelperExecutionContext.AddTagHelperAttribute(__tagHelperAttribute_3);
            await __tagHelperRunner.RunAsync(__tagHelperExecutionContext);
            if (!__tagHelperExecutionContext.Output.IsContentModified)
            {
                await __tagHelperExecutionContext.SetOutputContentAsync();
            }
            Write(__tagHelperExecutionContext.Output);
            __tagHelperExecutionContext = __tagHelperScopeManager.End();
            WriteLiteral(@"
            </div>
        </div>
    </div>
</div>

<div class=""container"">
    </div>
    <div class=""row"">
        <div class=""col-12 mb-5"">
            <div class=""card mb-2 bg-transparent no-shadow d-none d-md-block"">
                <div class=""card-body pt-0 pb-0 sh-3"">
                    <div class=""row g-0 h-100 justify-content-between align-content-center"">
                        <div class=""col-6 col-md-1 d-flex align-items-center text-alternate text-medium text-muted text-small"">Image</div>
                        <div class=""col-6 col-md-1 d-flex align-items-center text-alternate text-medium text-muted text-small"">Name</div>
                        <div class=""col-6 col-md-1 d-flex align-items-center text-alternate text-medium text-muted text-small"">Price</div>
                        <div class=""col-6 col-md-1 d-flex align-items-center text-alternate text-medium text-muted text-small"">Raiting</div>
                        <div class=""col-6 col-md-1 d-flex align-items-center t");
            WriteLiteral(@"ext-alternate text-medium text-muted text-small"">Stock</div>
                        <div class=""col-6 col-md-1 d-flex align-items-center text-alternate text-medium text-muted text-small"">Desc</div>
                        <div class=""col-6 col-md-1 d-flex align-items-center text-alternate text-medium text-muted text-small"">Category</div>
                        <div class=""col-6 col-md-1 d-flex align-items-center text-alternate text-medium text-muted text-small"">Status</div>
                        <div class=""col-6 col-md-1 d-flex align-items-center text-alternate text-medium text-muted text-small"">Actions</div>
                    </div>
                </div>
            </div>
            <div>
");
#nullable restore
#line 75 "C:\Users\ELNUR\Desktop\Backend Home\Visual Studio\Pronia\Pronia\Areas\Manage\Views\Product\Index.cshtml"
                 foreach (var item in Model)
                {

#line default
#line hidden
#nullable disable
            WriteLiteral(@"                    <div class=""card mb-2"">
                        <div class=""card-body pt-0 pb-0 sh-21 sh-md-8"">
                            <div class=""row g-0 h-100 justify-content-between align-content-center"">
                                <div class=""col-11 col-md-1 d-flex flex-column justify-content-center mb-2 mb-md-0 h-md-100 position-relative"">
                                    <div class=""text-muted text-small d-md-none"">Image</div>
");
#nullable restore
#line 82 "C:\Users\ELNUR\Desktop\Backend Home\Visual Studio\Pronia\Pronia\Areas\Manage\Views\Product\Index.cshtml"
                                     if (item.ProductImages.Where(pi => pi.IsMain == true).FirstOrDefault() != null)
                                    {

#line default
#line hidden
#nullable disable
            WriteLiteral("                                        ");
            __tagHelperExecutionContext = __tagHelperScopeManager.Begin("img", global::Microsoft.AspNetCore.Razor.TagHelpers.TagMode.SelfClosing, "33c1d7bd286af87ad4aa38b6ae6e7502511cf31616304", async() => {
            }
            );
            __Microsoft_AspNetCore_Mvc_Razor_TagHelpers_UrlResolutionTagHelper = CreateTagHelper<global::Microsoft.AspNetCore.Mvc.Razor.TagHelpers.UrlResolutionTagHelper>();
            __tagHelperExecutionContext.Add(__Microsoft_AspNetCore_Mvc_Razor_TagHelpers_UrlResolutionTagHelper);
            BeginAddHtmlAttributeValues(__tagHelperExecutionContext, "src", 2, global::Microsoft.AspNetCore.Razor.TagHelpers.HtmlAttributeValueStyle.DoubleQuotes);
            AddHtmlAttributeValue("", 4542, "~/assets/images/product/", 4542, 24, true);
#nullable restore
#line 84 "C:\Users\ELNUR\Desktop\Backend Home\Visual Studio\Pronia\Pronia\Areas\Manage\Views\Product\Index.cshtml"
AddHtmlAttributeValue("", 4566, item.ProductImages.Where(x=>x.IsMain==true).FirstOrDefault().Image, 4566, 67, false);

#line default
#line hidden
#nullable disable
            EndAddHtmlAttributeValues(__tagHelperExecutionContext);
            __tagHelperExecutionContext.AddHtmlAttribute(__tagHelperAttribute_4);
            __tagHelperExecutionContext.AddHtmlAttribute(__tagHelperAttribute_5);
            await __tagHelperRunner.RunAsync(__tagHelperExecutionContext);
            if (!__tagHelperExecutionContext.Output.IsContentModified)
            {
                await __tagHelperExecutionContext.SetOutputContentAsync();
            }
            Write(__tagHelperExecutionContext.Output);
            __tagHelperExecutionContext = __tagHelperScopeManager.End();
            WriteLiteral("\r\n");
#nullable restore
#line 85 "C:\Users\ELNUR\Desktop\Backend Home\Visual Studio\Pronia\Pronia\Areas\Manage\Views\Product\Index.cshtml"
                                    }

#line default
#line hidden
#nullable disable
            WriteLiteral(@"                                </div>
                                <div class=""col-6 col-md-1 d-flex flex-column justify-content-center mb-2 mb-md-0"">
                                    <div class=""text-muted text-small d-md-none"">Name</div>
                                    <div class=""text-alternate"">");
#nullable restore
#line 89 "C:\Users\ELNUR\Desktop\Backend Home\Visual Studio\Pronia\Pronia\Areas\Manage\Views\Product\Index.cshtml"
                                                           Write(item.Name);

#line default
#line hidden
#nullable disable
            WriteLiteral(@"</div>
                                </div>
                                <div class=""col-6 col-md-1 d-flex flex-column justify-content-center mb-2 mb-md-0"">
                                    <div class=""text-muted text-small d-md-none"">Price</div>
                                    <div class=""text-alternate"">
                                        <span>
                                            <span class=""text-small"">$</span>
                                            ");
#nullable restore
#line 96 "C:\Users\ELNUR\Desktop\Backend Home\Visual Studio\Pronia\Pronia\Areas\Manage\Views\Product\Index.cshtml"
                                       Write(item.Price);

#line default
#line hidden
#nullable disable
            WriteLiteral(@"
                                        </span>
                                    </div>
                                </div>
                                <div class=""col-6 col-md-1 d-flex flex-column justify-content-center mb-2 mb-md-0"">
                                    <div class=""text-muted text-small d-md-none"">Raiting</div>
                                    <div class=""text-alternate"">");
#nullable restore
#line 102 "C:\Users\ELNUR\Desktop\Backend Home\Visual Studio\Pronia\Pronia\Areas\Manage\Views\Product\Index.cshtml"
                                                           Write(item.Raiting);

#line default
#line hidden
#nullable disable
            WriteLiteral(@"</div>
                                </div>
                                <div class=""col-6 col-md-1 d-flex flex-column justify-content-center mb-2 mb-md-0"">
                                    <div class=""text-muted text-small d-md-none"">Stock Count</div>
                                    <div class=""text-alternate"">");
#nullable restore
#line 106 "C:\Users\ELNUR\Desktop\Backend Home\Visual Studio\Pronia\Pronia\Areas\Manage\Views\Product\Index.cshtml"
                                                           Write(item.StockCount);

#line default
#line hidden
#nullable disable
            WriteLiteral(@"</div>
                                </div>
                                <div class=""col-6 col-md-1 d-flex flex-column justify-content-center mb-2 mb-md-0"">
                                    <div class=""text-muted text-small d-md-none"">Description</div>
                                    <div class=""text-alternate"">");
#nullable restore
#line 110 "C:\Users\ELNUR\Desktop\Backend Home\Visual Studio\Pronia\Pronia\Areas\Manage\Views\Product\Index.cshtml"
                                                           Write(item.Description);

#line default
#line hidden
#nullable disable
            WriteLiteral(@"</div>
                                </div>
                                <div class=""col-6 col-md-1 d-flex flex-column justify-content-center mb-2 mb-md-0"">
                                    <div class=""text-muted text-small d-md-none"">Category</div>
                                    <div class=""text-alternate"">");
#nullable restore
#line 114 "C:\Users\ELNUR\Desktop\Backend Home\Visual Studio\Pronia\Pronia\Areas\Manage\Views\Product\Index.cshtml"
                                                           Write(item.Category.Name);

#line default
#line hidden
#nullable disable
            WriteLiteral(@"</div>
                                </div>
                                <div class=""col-6 col-md-1 d-flex flex-column justify-content-center mb-2 mb-md-0"">
                                    <div class=""text-muted text-small d-md-none"">Status</div>
                                    <div class=""text-alternate"">
                                        ");
#nullable restore
#line 119 "C:\Users\ELNUR\Desktop\Backend Home\Visual Studio\Pronia\Pronia\Areas\Manage\Views\Product\Index.cshtml"
                                    Write(item.IsDeleted==false?Html.Raw("<span class='badge rounded-pill bg-outline-success'>Visible</span>"): Html.Raw("<span class='badge rounded-pill bg-outline-danger'>Not Visible</span>"));

#line default
#line hidden
#nullable disable
            WriteLiteral(@"
                                    </div>
                                </div>
                                <div class=""col-1 d-flex flex-row mb-2 mb-lg-0 align-items-center order-2 order-lg-last justify-content-lg-center"">
                                    ");
            __tagHelperExecutionContext = __tagHelperScopeManager.Begin("a", global::Microsoft.AspNetCore.Razor.TagHelpers.TagMode.StartTagAndEndTag, "33c1d7bd286af87ad4aa38b6ae6e7502511cf31623418", async() => {
                WriteLiteral("Edit");
            }
            );
            __Microsoft_AspNetCore_Mvc_TagHelpers_AnchorTagHelper = CreateTagHelper<global::Microsoft.AspNetCore.Mvc.TagHelpers.AnchorTagHelper>();
            __tagHelperExecutionContext.Add(__Microsoft_AspNetCore_Mvc_TagHelpers_AnchorTagHelper);
            __Microsoft_AspNetCore_Mvc_TagHelpers_AnchorTagHelper.Action = (string)__tagHelperAttribute_6.Value;
            __tagHelperExecutionContext.AddTagHelperAttribute(__tagHelperAttribute_6);
            if (__Microsoft_AspNetCore_Mvc_TagHelpers_AnchorTagHelper.RouteValues == null)
            {
                throw new InvalidOperationException(InvalidTagHelperIndexerAssignment("asp-route-id", "Microsoft.AspNetCore.Mvc.TagHelpers.AnchorTagHelper", "RouteValues"));
            }
            BeginWriteTagHelperAttribute();
#nullable restore
#line 123 "C:\Users\ELNUR\Desktop\Backend Home\Visual Studio\Pronia\Pronia\Areas\Manage\Views\Product\Index.cshtml"
                                                           WriteLiteral(item.Id);

#line default
#line hidden
#nullable disable
            __tagHelperStringValueBuffer = EndWriteTagHelperAttribute();
            __Microsoft_AspNetCore_Mvc_TagHelpers_AnchorTagHelper.RouteValues["id"] = __tagHelperStringValueBuffer;
            __tagHelperExecutionContext.AddTagHelperAttribute("asp-route-id", __Microsoft_AspNetCore_Mvc_TagHelpers_AnchorTagHelper.RouteValues["id"], global::Microsoft.AspNetCore.Razor.TagHelpers.HtmlAttributeValueStyle.DoubleQuotes);
            __tagHelperExecutionContext.AddHtmlAttribute(__tagHelperAttribute_7);
            await __tagHelperRunner.RunAsync(__tagHelperExecutionContext);
            if (!__tagHelperExecutionContext.Output.IsContentModified)
            {
                await __tagHelperExecutionContext.SetOutputContentAsync();
            }
            Write(__tagHelperExecutionContext.Output);
            __tagHelperExecutionContext = __tagHelperScopeManager.End();
            WriteLiteral("\r\n\r\n");
#nullable restore
#line 125 "C:\Users\ELNUR\Desktop\Backend Home\Visual Studio\Pronia\Pronia\Areas\Manage\Views\Product\Index.cshtml"
                                     if(@item.IsDeleted==false)
                                    {

#line default
#line hidden
#nullable disable
            WriteLiteral("                                    <button type=\"button\" class=\"btn btn-danger mx-lg-1\" data-id=\"");
#nullable restore
#line 127 "C:\Users\ELNUR\Desktop\Backend Home\Visual Studio\Pronia\Pronia\Areas\Manage\Views\Product\Index.cshtml"
                                                                                             Write(item.Id);

#line default
#line hidden
#nullable disable
            WriteLiteral("\" data-toggle=\"modal\" data-target=\"#deleteModal\">Delete</button>\r\n");
#nullable restore
#line 128 "C:\Users\ELNUR\Desktop\Backend Home\Visual Studio\Pronia\Pronia\Areas\Manage\Views\Product\Index.cshtml"
                                    }
                                    else{

#line default
#line hidden
#nullable disable
            WriteLiteral("                                        <button type=\"button\" class=\"btn btn-primary mx-lg-1\" data-id=\"");
#nullable restore
#line 130 "C:\Users\ELNUR\Desktop\Backend Home\Visual Studio\Pronia\Pronia\Areas\Manage\Views\Product\Index.cshtml"
                                                                                                  Write(item.Id);

#line default
#line hidden
#nullable disable
            WriteLiteral("\" data-toggle=\"modal\" data-target=\"#ActiveModal\">Active</button>\r\n                                        <button type=\"button\" class=\"btn btn-primary\" data-id=\"");
#nullable restore
#line 131 "C:\Users\ELNUR\Desktop\Backend Home\Visual Studio\Pronia\Pronia\Areas\Manage\Views\Product\Index.cshtml"
                                                                                          Write(item.Id);

#line default
#line hidden
#nullable disable
            WriteLiteral("\" data-toggle=\"modal\" data-target=\"#HarddeleteModal\">Hard Delete</button>\r\n");
#nullable restore
#line 132 "C:\Users\ELNUR\Desktop\Backend Home\Visual Studio\Pronia\Pronia\Areas\Manage\Views\Product\Index.cshtml"
                                    }

#line default
#line hidden
#nullable disable
            WriteLiteral("\r\n                                </div>\r\n                            </div>\r\n                        </div>\r\n                    </div>\r\n");
#nullable restore
#line 138 "C:\Users\ELNUR\Desktop\Backend Home\Visual Studio\Pronia\Pronia\Areas\Manage\Views\Product\Index.cshtml"
                }

#line default
#line hidden
#nullable disable
            WriteLiteral(@"            </div>
        </div>
    </div>
    <div class=""d-flex justify-content-center"">
        <nav>
            <ul class=""pagination"">
                <li class=""page-item active""><a class=""page-link shadow"" href=""#"">1</a></li>
            </ul>
        </nav>
    </div>
");
            DefineSection("scripts", async() => {
                WriteLiteral(@"
<script src=""https://code.jquery.com/jquery-3.2.1.slim.min.js"" integrity=""sha384-KJ3o2DKtIkvYIK3UENzmM7KCkRr/rE9/Qpg6aAZGJwFDMVNA/GpGFF93hXpG5KkN"" crossorigin=""anonymous""></script>
<script src=""https://cdn.jsdelivr.net/npm/popper.js@1.12.9/dist/umd/popper.min.js"" integrity=""sha384-ApNbgh9B+Y1QKtv3Rn7W3mgPxhU9K/ScQsAP7hUibX39j7fakFPskvXusvfa0b4Q"" crossorigin=""anonymous""></script>
<script src=""https://cdn.jsdelivr.net/npm/bootstrap@4.0.0/dist/js/bootstrap.min.js"" integrity=""sha384-JZR6Spejh4U02d8jOt6vLEHfe/JQGiRRSQQxSfFWpi1MquVdAyjUar5+76PVCmYl"" crossorigin=""anonymous""></script>
<script>
    $(""button[data-toggle='modal']"").click(function(){
        let FormId = $(this).attr(""data-target"")
        console.log(FormId)
        let FormIdStr = `${FormId} form`
        console.log(FormIdStr)
        let url = $(FormIdStr).attr(""action"")
        console.log(url)
        $(FormIdStr).attr(""action"",url + ""/"" + $(this).attr(""data-id""))
    })
</script>
");
            }
            );
        }
        #pragma warning restore 1998
        #nullable restore
        [global::Microsoft.AspNetCore.Mvc.Razor.Internal.RazorInjectAttribute]
        public global::Microsoft.AspNetCore.Mvc.ViewFeatures.IModelExpressionProvider ModelExpressionProvider { get; private set; } = default!;
        #nullable disable
        #nullable restore
        [global::Microsoft.AspNetCore.Mvc.Razor.Internal.RazorInjectAttribute]
        public global::Microsoft.AspNetCore.Mvc.IUrlHelper Url { get; private set; } = default!;
        #nullable disable
        #nullable restore
        [global::Microsoft.AspNetCore.Mvc.Razor.Internal.RazorInjectAttribute]
        public global::Microsoft.AspNetCore.Mvc.IViewComponentHelper Component { get; private set; } = default!;
        #nullable disable
        #nullable restore
        [global::Microsoft.AspNetCore.Mvc.Razor.Internal.RazorInjectAttribute]
        public global::Microsoft.AspNetCore.Mvc.Rendering.IJsonHelper Json { get; private set; } = default!;
        #nullable disable
        #nullable restore
        [global::Microsoft.AspNetCore.Mvc.Razor.Internal.RazorInjectAttribute]
        public global::Microsoft.AspNetCore.Mvc.Rendering.IHtmlHelper<List<Product>> Html { get; private set; } = default!;
        #nullable disable
    }
}
#pragma warning restore 1591
