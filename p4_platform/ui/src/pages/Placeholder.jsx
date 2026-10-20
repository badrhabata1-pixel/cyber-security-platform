export default function Placeholder({ title, notFound = false }) {
  return (
    <div className="placeholder">
      <div className="placeholder-icon" aria-hidden="true">
        {notFound ? '?' : '⚙'}
      </div>
      <h1>{notFound ? title : 'Module Under Construction'}</h1>
      <p>
        {notFound
          ? 'The page you are looking for does not exist or you do not have access to it.'
          : `${title} is not available yet. Check back soon.`}
      </p>
    </div>
  )
}
