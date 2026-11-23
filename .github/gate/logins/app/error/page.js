export default async function E({ searchParams }) { const p = await searchParams; return <p>Sorry, something went wrong ({p.code})</p> }
