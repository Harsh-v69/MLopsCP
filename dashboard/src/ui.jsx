// Small shared presentational pieces. No data logic lives here.

export function PageHead({ title, children }) {
  return (
    <div className="page-head">
      <h2>{title}</h2>
      <p>{children}</p>
    </div>
  )
}

export function Badge({ tone = 'info', large = false, children, ...rest }) {
  return (
    <span className={`badge badge-${tone}${large ? ' badge-lg' : ''}`} {...rest}>
      {children}
    </span>
  )
}

export function Skeleton({ height = 120 }) {
  return <div className="skeleton" style={{ height }} aria-hidden="true" />
}

export function ErrorBox({ testId, title, error, onRetry }) {
  return (
    <div role="alert" data-testid={testId}>
      <strong>{title}</strong>
      <div>{error.message}</div>
      <div className="muted" style={{ margin: '6px 0 10px' }}>
        Check that the MLShield API is running on localhost:8000 and try again.
      </div>
      {onRetry && (
        <button className="ghost" onClick={onRetry}>
          Try again
        </button>
      )}
    </div>
  )
}
