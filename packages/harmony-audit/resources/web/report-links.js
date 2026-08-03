const htmlReport = document.querySelector("#open-report");
const markdownReport = document.querySelector("#open-markdown");

markdownReport?.addEventListener("click", (event) => {
  const htmlUrl = htmlReport?.getAttribute("href");
  if (!htmlUrl) { event.preventDefault(); return; }
  markdownReport.setAttribute("href", htmlUrl.replace("report-html", "report-markdown"));
});
