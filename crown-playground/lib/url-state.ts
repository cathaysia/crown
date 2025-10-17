export function getUrlParams(): URLSearchParams {
  if (typeof window !== 'undefined') {
    return new URLSearchParams(window.location.search);
  }
  return new URLSearchParams();
}

export function updateUrlParams(params: Record<string, string | undefined>) {
  if (typeof window === 'undefined') return;

  const urlParams = new URLSearchParams(window.location.search);

  Object.entries(params).forEach(([key, value]) => {
    if (value === undefined || value === '') {
      urlParams.delete(key);
    } else {
      urlParams.set(key, value);
    }
  });

  const newUrl = `${window.location.pathname}${urlParams.toString() ? '?' + urlParams.toString() : ''}`;
  window.history.replaceState({}, '', newUrl);
}

export function getParamValue(key: string, defaultValue: string = ''): string {
  const params = getUrlParams();
  return params.get(key) || defaultValue;
}

export function useUrlState<T extends string>(
  key: string,
  defaultValue: T,
  setValue: (value: T) => void,
): [T, (value: T) => void] {
  const updateState = (value: T) => {
    setValue(value);
    updateUrlParams({ [key]: value });
  };

  return [getParamValue(key, defaultValue) as T, updateState];
}
