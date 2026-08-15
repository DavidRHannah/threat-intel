import React from 'react';

/**
 * Without a boundary, any exception thrown while rendering unmounts the entire app and
 * leaves a blank white page with nothing but a console trace -- which is exactly how the
 * entity detail page failed. Catch it here so a broken panel stays a broken panel.
 */
export class ErrorBoundary extends React.Component {
  constructor(props) {
    super(props);
    this.state = { error: null };
  }

  static getDerivedStateFromError(error) {
    return { error };
  }

  componentDidCatch(error, info) {
    console.error('Render error caught by ErrorBoundary:', error, info);
  }

  render() {
    if (this.state.error) {
      return (
        <div className="page-container fade-in">
          <h2>Something went wrong rendering this page.</h2>
          <p className="text-muted">{String(this.state.error?.message || this.state.error)}</p>
          <button className="btn" onClick={() => this.setState({ error: null })}>
            Try again
          </button>
        </div>
      );
    }
    return this.props.children;
  }
}
